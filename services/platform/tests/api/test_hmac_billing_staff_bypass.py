"""
Tests for HMAC middleware billing staff UI bypass.

Verifies that session-authenticated staff users can access billing UI paths
(/billing/invoices/, /billing/reports/, etc.) without HMAC headers, while the
portal's payment endpoints (/api/billing/create-payment-intent/, etc.) require
HMAC authentication and are served through the real urlconf.

Related: Codex review finding CRITICAL-1 — billing HMAC gating breaks staff UI.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import resolve, reverse

from apps.billing import views as billing_views
from apps.common.middleware import PortalServiceHMACMiddleware
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

LOCMEM_TEST_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "hmac-billing-bypass-tests",
    }
}


@override_settings(CACHES=LOCMEM_TEST_CACHE, PLATFORM_API_SECRET="unit-test-secret")
class BillingStaffSessionBypassTests(TestCase):
    """Staff users accessing billing UI via browser should not need HMAC."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))

    def _make_staff_request(self, path: str) -> HttpResponse:
        """Create a GET request from an authenticated staff user (no HMAC headers)."""
        request = self.factory.get(path)
        # Simulate Django auth middleware having already authenticated a staff user
        user = MagicMock()
        user.is_authenticated = True
        user.is_staff = True
        user.email = "admin@pragmatichost.com"
        request.user = user
        return self.middleware(request)

    def _make_anonymous_request(self, path: str) -> HttpResponse:
        """Create a GET request from an unauthenticated user (no HMAC headers)."""
        request = self.factory.get(path)
        request.user = MagicMock(is_authenticated=False, is_staff=False)
        return self.middleware(request)

    # ── Staff UI paths: SHOULD be allowed with session auth ──

    def test_staff_can_access_billing_invoices(self) -> None:
        response = self._make_staff_request("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_invoice_detail(self) -> None:
        response = self._make_staff_request("/billing/invoices/42/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_proformas(self) -> None:
        response = self._make_staff_request("/billing/proformas/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_proforma_detail(self) -> None:
        response = self._make_staff_request("/billing/proformas/99/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_payments(self) -> None:
        response = self._make_staff_request("/billing/payments/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_reports(self) -> None:
        response = self._make_staff_request("/billing/reports/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_billing_vat_report(self) -> None:
        response = self._make_staff_request("/billing/reports/vat/")
        self.assertEqual(response.status_code, 200)

    def test_staff_can_access_efactura_dashboard(self) -> None:
        response = self._make_staff_request("/billing/e-factura/")
        self.assertEqual(response.status_code, 200)

    # ── Inter-service API paths: MUST require HMAC, even for staff ──

    def test_staff_cannot_reach_the_payment_endpoints_without_hmac(self) -> None:
        """The portal's payment endpoints are under /api/billing/; staff sessions get no bypass."""
        for path in ("/api/billing/create-payment-intent/", "/api/billing/confirm-payment/", "/api/billing/stripe-config/"):
            with self.subTest(path=path):
                self.assertEqual(self._make_staff_request(path).status_code, 401)

    def test_the_old_billing_api_paths_are_ordinary_staff_paths_now(self) -> None:
        """Nothing under /billing/ is HMAC-gated any more, so these pass the middleware.

        That they then reach no view (404) is proven through the real urlconf below, in
        PortalPaymentEndpointRoutingTests, and for the refund path in
        tests/billing/test_customer_refund_path_removed.py.
        """
        for path in (
            "/billing/create-payment-intent/",
            "/billing/confirm-payment/",
            "/billing/stripe-config/",
            "/billing/process-refund/",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._make_staff_request(path).status_code, 200)

    # ── Anonymous users ──

    def test_anonymous_billing_ui_passes_through_middleware(self) -> None:
        """Staff UI paths are not HMAC-gated; @login_required on the view handles auth."""
        response = self._make_anonymous_request("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_anonymous_cannot_access_billing_api(self) -> None:
        """Inter-service API paths require HMAC even for anonymous requests."""
        response = self._make_anonymous_request("/api/billing/create-payment-intent/")
        self.assertEqual(response.status_code, 401)


PAYMENT_ENDPOINTS = (
    ("api_create_payment_intent", "/api/billing/create-payment-intent/", "POST"),
    ("api_confirm_payment", "/api/billing/confirm-payment/", "POST"),
    ("api_stripe_config", "/api/billing/stripe-config/", "GET"),
)
PLATFORM_HMAC_REJECTION = {"error": "HMAC authentication failed"}


@override_settings(CACHES=LOCMEM_TEST_CACHE, PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class PortalPaymentEndpointRoutingTests(HMACTestMixin, TestCase):
    """The portal's payment endpoints live under /api/billing/, through the real urlconf.

    Platform's Caddy configuration publishes only /api/* on its hostname, so endpoints under
    /billing/ were unreachable for a portal on its own host. The middleware-only tests above
    wrap an always-200 callback and cannot show routing; these go through the test client.
    """

    def test_each_endpoint_reverses_and_resolves_under_api_billing(self) -> None:
        for name, path, _method in PAYMENT_ENDPOINTS:
            with self.subTest(name=name):
                self.assertEqual(reverse(f"api:api_billing:{name}"), path)
                self.assertIs(resolve(path).func, getattr(billing_views, name))

    def test_an_unsigned_request_gets_platforms_uniform_rejection(self) -> None:
        for name, path, method in PAYMENT_ENDPOINTS:
            with self.subTest(name=name):
                response = self.client.generic(method, path, b"{}", content_type="application/json")
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json(), PLATFORM_HMAC_REJECTION)

    def test_a_signed_request_reaches_the_view(self) -> None:
        for name, path, method in PAYMENT_ENDPOINTS:
            with self.subTest(name=name):
                response = self.portal_post(path, {}) if method == "POST" else self.portal_get(path)
                self.assertNotIn(response.status_code, {401, 404}, response.content)
                self.assertNotEqual(response.json(), PLATFORM_HMAC_REJECTION)

    def test_stripe_config_answers_from_the_view_in_english(self) -> None:
        # LocalisationMiddleware skips /api/; these views hard-code English, so the move
        # changes no output. Pinned on the one answer every test environment produces.
        response = self.portal_get("/api/billing/stripe-config/")
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.json(), {"success": False, "error": "Stripe integration disabled"})

    def test_the_old_billing_paths_are_gone(self) -> None:
        for _name, path, method in PAYMENT_ENDPOINTS:
            old_path = path.removeprefix("/api")
            with self.subTest(path=old_path):
                response = self.portal_post(old_path, {}) if method == "POST" else self.portal_get(old_path)
                self.assertEqual(response.status_code, 404, response.content)

    @override_settings(
        MAINTENANCE_MODE=True,
        MIDDLEWARE=[*HMAC_TEST_MIDDLEWARE[:6], "apps.common.middleware.MaintenanceModeMiddleware", *HMAC_TEST_MIDDLEWARE[6:]],
    )
    def test_maintenance_answers_the_portal_in_json(self) -> None:
        response = self.portal_get("/api/billing/stripe-config/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"], "maintenance")

    def test_the_views_refuse_a_request_the_middleware_did_not_authenticate(self) -> None:
        """Defence in depth: if the HMAC middleware is missing or bypassed, the views still refuse."""
        factory = RequestFactory()
        for name, path, method in PAYMENT_ENDPOINTS:
            with self.subTest(name=name):
                request = factory.generic(method, path, b"{}", content_type="application/json")
                response = getattr(billing_views, name)(request)
                self.assertEqual(response.status_code, 403, response.content)

    def test_the_signed_post_endpoints_stay_csrf_exempt(self) -> None:
        """The portal sends no CSRF token; the HMAC signature is the request's authenticity."""
        for name in ("api_create_payment_intent", "api_confirm_payment"):
            with self.subTest(name=name):
                self.assertIs(getattr(getattr(billing_views, name), "csrf_exempt", False), True)
