"""
Tests for HMAC middleware billing staff UI bypass.

Verifies that session-authenticated staff users can access billing UI paths
(/billing/invoices/, /billing/reports/, etc.) without HMAC headers, while
inter-service billing API paths (/billing/create-payment-intent/, etc.) still
require HMAC authentication.

Related: Codex review finding CRITICAL-1 — billing HMAC gating breaks staff UI.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common.middleware import PortalServiceHMACMiddleware

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

    # ── Inter-service API paths: MUST still require HMAC ──

    def test_staff_cannot_access_create_payment_intent_without_hmac(self) -> None:
        """Inter-service billing endpoints require HMAC even for staff."""
        response = self._make_staff_request("/billing/create-payment-intent/")
        self.assertEqual(response.status_code, 401)

    def test_staff_cannot_access_confirm_payment_without_hmac(self) -> None:
        response = self._make_staff_request("/billing/confirm-payment/")
        self.assertEqual(response.status_code, 401)

    def test_staff_cannot_access_create_subscription_without_hmac(self) -> None:
        response = self._make_staff_request("/billing/create-subscription/")
        self.assertEqual(response.status_code, 401)

    def test_staff_cannot_access_stripe_config_without_hmac(self) -> None:
        response = self._make_staff_request("/billing/stripe-config/")
        self.assertEqual(response.status_code, 401)

    def test_staff_cannot_access_process_refund_without_hmac(self) -> None:
        response = self._make_staff_request("/billing/process-refund/")
        self.assertEqual(response.status_code, 401)

    # ── Anonymous users ──

    def test_anonymous_billing_ui_passes_through_middleware(self) -> None:
        """Staff UI paths are not HMAC-gated; @login_required on the view handles auth."""
        response = self._make_anonymous_request("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_anonymous_cannot_access_billing_api(self) -> None:
        """Inter-service API paths require HMAC even for anonymous requests."""
        response = self._make_anonymous_request("/billing/create-payment-intent/")
        self.assertEqual(response.status_code, 401)
