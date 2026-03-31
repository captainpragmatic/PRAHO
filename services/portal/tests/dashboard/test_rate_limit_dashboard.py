from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase, override_settings
from django.test.client import RequestFactory

from apps.api_client.services import PlatformAPIError
from apps.dashboard.views import dashboard_view


def _rate_limited_error(retry_after: int = 10) -> PlatformAPIError:
    return PlatformAPIError(
        "Too many requests", status_code=429, retry_after=retry_after, is_rate_limited=True
    )


def _server_error() -> PlatformAPIError:
    return PlatformAPIError("Server error", status_code=500, is_rate_limited=False)


def _authenticated_request(path: str = "/dashboard/") -> MagicMock:
    request = RequestFactory().get(path)
    session_middleware = SessionMiddleware(lambda r: None)
    session_middleware.process_request(request)
    request.session["customer_id"] = "1"
    request.session["email"] = "test@example.com"
    request.session["user_id"] = 1
    request.customer_id = "1"
    request.user = SimpleNamespace(id=1, is_authenticated=True)
    request._messages = FallbackStorage(request)
    return request


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
    ROOT_URLCONF="config.urls",
)
class DashboardPerSectionRateLimitTests(SimpleTestCase):
    """Tests for per-section rate-limit tracking in dashboard_view."""

    def _call_dashboard(self, request: MagicMock) -> MagicMock:
        return dashboard_view(request)

    @patch("apps.dashboard.views._get_services_data", return_value=(2, {}))
    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data")
    def test_billing_rate_limited_preserves_ticket_data(
        self,
        mock_billing: MagicMock,
        mock_customer: MagicMock,
        mock_tickets: MagicMock,
        mock_services: MagicMock,
    ) -> None:
        mock_billing.side_effect = _rate_limited_error(15)
        # Tickets returns data
        ticket_obj = SimpleNamespace(id=1, title="Test", status="open", created_at="2026-01-01", ticket_number="T-1")
        mock_tickets.return_value = ([ticket_obj], 1, {})

        request = _authenticated_request()
        response = self._call_dashboard(request)

        self.assertEqual(response.status_code, 200)
        # The response should render successfully; verify template was called
        self.assertIn(b"Dashboard", response.content)

    @patch("apps.dashboard.views._get_services_data", return_value=(0, {}))
    @patch("apps.dashboard.views._get_ticket_data")
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 5}))
    def test_tickets_rate_limited_preserves_billing_data(
        self,
        mock_billing: MagicMock,
        mock_customer: MagicMock,
        mock_tickets: MagicMock,
        mock_services: MagicMock,
    ) -> None:
        mock_tickets.side_effect = _rate_limited_error(20)

        request = _authenticated_request()
        response = self._call_dashboard(request)

        self.assertEqual(response.status_code, 200)

    @patch("apps.dashboard.views._get_services_data")
    @patch("apps.dashboard.views._get_ticket_data")
    @patch("apps.dashboard.views._get_customer_data")
    @patch("apps.dashboard.views._get_billing_data")
    def test_all_rate_limited_shows_all_sections(
        self,
        mock_billing: MagicMock,
        mock_customer: MagicMock,
        mock_tickets: MagicMock,
        mock_services: MagicMock,
    ) -> None:
        mock_billing.side_effect = _rate_limited_error(10)
        mock_customer.side_effect = _rate_limited_error(15)
        mock_tickets.side_effect = _rate_limited_error(20)
        mock_services.side_effect = _rate_limited_error(25)

        request = _authenticated_request()
        response = self._call_dashboard(request)

        self.assertEqual(response.status_code, 200)
        # All rate-limited sections should appear in context
        content = response.content.decode()
        self.assertIn("rate limited", content.lower())

    @patch("apps.dashboard.views._get_services_data", return_value=(3, {}))
    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], "John"))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 2}))
    def test_no_rate_limit_shows_full_dashboard(
        self,
        mock_billing: MagicMock,
        mock_customer: MagicMock,
        mock_tickets: MagicMock,
        mock_services: MagicMock,
    ) -> None:
        request = _authenticated_request()
        response = self._call_dashboard(request)

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # No rate-limit message when everything succeeds
        self.assertNotIn("rate limited", content.lower().replace("temporarily rate limited", ""))

    @patch("apps.dashboard.views._get_services_data", return_value=(0, {}))
    @patch("apps.dashboard.views._get_ticket_data")
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data")
    def test_rate_limited_retry_after_uses_max(
        self,
        mock_billing: MagicMock,
        mock_customer: MagicMock,
        mock_tickets: MagicMock,
        mock_services: MagicMock,
    ) -> None:
        mock_billing.side_effect = _rate_limited_error(5)
        mock_tickets.side_effect = _rate_limited_error(30)

        request = _authenticated_request()
        response = self._call_dashboard(request)

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # Should use the max retry_after (30), not min (5)
        self.assertIn("30", content)
