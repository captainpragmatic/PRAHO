"""Regression tests for the portal service-usage identity boundary (#230)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import RequestFactory, SimpleTestCase

from apps.services.views import service_plans, service_usage


class ServiceUsageIdentityTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request(self, *, customer_id: object | None, user_id: object | None, period: str = "30d"):
        request = self.factory.get("/services/55/usage/", {"period": period})
        request.session = {}
        if customer_id is not None:
            request.session["customer_id"] = customer_id
        if user_id is not None:
            request.session["user_id"] = user_id
        return request

    @patch("apps.services.views.services_api.get_service_usage")
    def test_passes_distinct_customer_and_user_ids_to_platform(self, mock_get_usage: MagicMock) -> None:
        mock_get_usage.return_value = {"bandwidth_used": 12, "storage_used": 3}
        request = self._request(customer_id="101", user_id="7", period="90d")

        response = service_usage(request, service_id=55)

        self.assertEqual(response.status_code, 200)
        mock_get_usage.assert_called_once_with(101, 7, 55, period="90d")

    @patch("apps.services.views.services_api.get_service_usage")
    def test_request_customer_id_takes_precedence_over_session(self, mock_get_usage: MagicMock) -> None:
        mock_get_usage.return_value = {"bandwidth_used": 12, "storage_used": 3}
        request = self._request(customer_id=101, user_id=7)
        request.customer_id = "202"

        response = service_usage(request, service_id=55)

        self.assertEqual(response.status_code, 200)
        mock_get_usage.assert_called_once_with(202, 7, 55, period="30d")

    @patch("apps.services.views.services_api.get_service_usage")
    def test_uses_middleware_normalized_user_id_for_legacy_session(self, mock_get_usage: MagicMock) -> None:
        mock_get_usage.return_value = {"bandwidth_used": 12, "storage_used": 3}
        request = self._request(customer_id=7, user_id=None)
        request.customer_id = "202"
        request.user_id = "7"

        response = service_usage(request, service_id=55)

        self.assertEqual(response.status_code, 200)
        mock_get_usage.assert_called_once_with(202, 7, 55, period="30d")

    @patch("apps.services.views.services_api.get_service_usage")
    def test_invalid_request_customer_id_does_not_fall_back_to_session(
        self, mock_get_usage: MagicMock
    ) -> None:
        for invalid_customer_id in (0, ""):
            with self.subTest(customer_id=invalid_customer_id):
                mock_get_usage.reset_mock()
                request = self._request(customer_id=101, user_id=7)
                request.customer_id = invalid_customer_id

                response = service_usage(request, service_id=55)

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, "/login/")
                mock_get_usage.assert_not_called()

    @patch("apps.services.views.services_api.get_service_usage")
    def test_invalid_or_missing_identity_redirects_without_platform_call(self, mock_get_usage: MagicMock) -> None:
        invalid_identities = [
            (None, 7),
            (101, None),
            ("invalid", 7),
            (101, "invalid"),
            (0, 7),
            (101, 0),
            (-1, 7),
            (101, -1),
            (True, 7),
            (101, True),
        ]

        for customer_id, user_id in invalid_identities:
            with self.subTest(customer_id=customer_id, user_id=user_id):
                mock_get_usage.reset_mock()
                request = self._request(customer_id=customer_id, user_id=user_id)

                response = service_usage(request, service_id=55)

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, "/login/")
                mock_get_usage.assert_not_called()


class ServicePlansIdentityTests(SimpleTestCase):
    """service_plans was the one services view left on the old extraction shape:
    truthiness fallback plus int(customer_id or 0) — the exact pattern the
    shared parser exists to remove (review of #230)."""

    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request(self, *, customer_id: object | None, user_id: object | None):
        request = self.factory.get("/services/plans/")
        request.session = {}
        if customer_id is not None:
            request.session["customer_id"] = customer_id
        if user_id is not None:
            request.session["user_id"] = user_id
        return request

    @patch("apps.services.views.services_api.get_available_plans")
    def test_plans_use_validated_integer_identity(self, mock_plans: MagicMock) -> None:
        mock_plans.return_value = []
        request = self._request(customer_id="101", user_id="7")

        response = service_plans(request)

        self.assertEqual(response.status_code, 200)
        mock_plans.assert_called_once_with(101, "")

    @patch("apps.services.views.services_api.get_available_plans")
    def test_plans_invalid_request_customer_id_fails_closed(self, mock_plans: MagicMock) -> None:
        request = self._request(customer_id=101, user_id=7)
        request.customer_id = 0

        response = service_plans(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login/")
        mock_plans.assert_not_called()
