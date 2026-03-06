from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.billing.services import BillingDataSyncService, InvoiceViewService


def _rate_limited_error() -> PlatformAPIError:
    return PlatformAPIError("Too many requests", status_code=429, retry_after=10, is_rate_limited=True)


def _server_error() -> PlatformAPIError:
    return PlatformAPIError("Server error", status_code=500, is_rate_limited=False)


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
)
class InvoiceViewServiceRateLimitTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = InvoiceViewService()
        self.service.api_client = MagicMock()

    def test_get_customer_invoices_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError) as ctx:
            self.service.get_customer_invoices(1, 1)
        self.assertTrue(ctx.exception.is_rate_limited)

    def test_get_customer_invoices_returns_fallback_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.get_customer_invoices(1, 1)
        self.assertEqual(result, [])

    def test_get_invoice_detail_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_invoice_detail("INV-001", 1, 1)

    def test_get_invoice_detail_returns_none_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.get_invoice_detail("INV-001", 1, 1)
        self.assertIsNone(result)

    def test_get_invoice_summary_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_invoice_summary(1, 1)

    def test_get_invoice_summary_returns_empty_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.get_invoice_summary(1, 1)
        self.assertEqual(result["total_invoices"], 0)

    def test_get_customer_proformas_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_customer_proformas(1, 1)

    def test_get_customer_proformas_returns_fallback_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.get_customer_proformas(1, 1)
        self.assertEqual(result, [])

    def test_get_proforma_detail_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_proforma_detail("PF-001", 1, 1)

    def test_get_proforma_detail_returns_none_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.get_proforma_detail("PF-001", 1, 1)
        self.assertIsNone(result)

    def test_get_payment_methods_reraises_rate_limited(self) -> None:
        self.service.api_client.get_payment_methods.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_payment_methods(1, 1)

    def test_get_payment_methods_returns_empty_on_server_error(self) -> None:
        self.service.api_client.get_payment_methods.side_effect = _server_error()
        result = self.service.get_payment_methods(1, 1)
        self.assertEqual(result, [])

    def test_request_refund_reraises_rate_limited(self) -> None:
        self.service.api_client.post.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.request_refund("INV-001", 1, 1)

    def test_request_refund_returns_error_on_server_error(self) -> None:
        self.service.api_client.post.side_effect = _server_error()
        result = self.service.request_refund("INV-001", 1, 1)
        self.assertFalse(result["success"])


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
)
class BillingDataSyncServiceRateLimitTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = BillingDataSyncService()
        self.service.api_client = MagicMock()

    def test_get_currencies_reraises_rate_limited(self) -> None:
        self.service.api_client.get.side_effect = _rate_limited_error()
        with self.assertRaises(PlatformAPIError):
            self.service.get_currencies()

    def test_get_currencies_returns_empty_on_server_error(self) -> None:
        self.service.api_client.get.side_effect = _server_error()
        result = self.service.get_currencies()
        self.assertEqual(result, [])

    def test_sync_customer_invoices_reraises_rate_limited(self) -> None:
        with patch("apps.billing.services.InvoiceViewService") as mock_cls:
            mock_instance = mock_cls.return_value
            mock_instance.get_customer_invoices.side_effect = _rate_limited_error()
            with self.assertRaises(PlatformAPIError):
                self.service.sync_customer_invoices(1, 1)

    def test_sync_customer_invoices_returns_empty_on_server_error(self) -> None:
        with patch("apps.billing.services.InvoiceViewService") as mock_cls:
            mock_instance = mock_cls.return_value
            mock_instance.get_customer_invoices.side_effect = _server_error()
            result = self.service.sync_customer_invoices(1, 1)
            self.assertEqual(result, [])
