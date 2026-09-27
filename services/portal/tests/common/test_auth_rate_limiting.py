"""Regression tests for Portal authentication attempt accounting."""

import json
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from requests import Response

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


@override_settings(
    RATE_LIMITING_ENABLED=True,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "auth-rate-limit-tests",
        }
    },
)
class AuthenticationRateLimitTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        response = Response()
        response.status_code = 200
        response._content = b'{"success": false}'
        transport = patch("apps.api_client.services.portal_request", return_value=response)
        transport.start()
        self.addCleanup(transport.stop)
        self.email = "login@example.com"
        self.credentials = {"email": self.email, "password": "test-password"}
        self.ip_key = "auth_ip_attempts_127.0.0.1"
        self.account_key = f"auth_account_attempts_{self.email}"
        self.volume_key = "auth_volume_ip_127.0.0.1"

    def test_failed_logins_are_counted_and_sixth_is_throttled(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            for _ in range(5):
                response = self.client.post(reverse("users:login"), self.credentials)
                self.assertEqual(response.status_code, 200)

            self.assertEqual(cache.get(self.ip_key), 5)
            self.assertEqual(cache.get(self.account_key), 5)
            response = self.client.post(reverse("users:login"), self.credentials, follow=False)
            self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
            self.assertIn(
                "Too many authentication attempts",
                " ".join(str(message) for message in get_messages(response.wsgi_request)),
            )
            response = self.client.post(reverse("users:login"), self.credentials, HTTP_HX_REQUEST="true")
            self.assertEqual(response.status_code, 429)
            self.assertIn("Too many authentication attempts", response.json()["error"])
            self.assertEqual(response.json()["retry_after"], 900)
            self.assertEqual(response.json()["attempts_remaining"], 0)
            self.assertEqual(cache.get(self.ip_key), 5)
            self.assertEqual(cache.get(self.account_key), 5)

    def test_successful_login_clears_counters(self) -> None:
        cache.set(self.ip_key, 3, 900)
        cache.set(self.account_key, 3, 1800)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(cache.get(self.ip_key), 4)
            self.assertEqual(cache.get(self.account_key), 4)

            platform.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 1,
                "customer_id": 1,
                "customer_data": {},
            }
            platform.post.return_value = {"success": True, "results": []}
            platform.get_user_customers.return_value = []
            platform.get_customer_profile.return_value = {}
            response = self.client.post(reverse("users:login"), self.credentials)

        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)
        self.assertEqual(self.client.session["user_id"], 1)
        self.assertIsNone(cache.get(self.ip_key))
        self.assertIsNone(cache.get(self.account_key))

    def test_failed_login_does_not_clear_existing_counter(self) -> None:
        cache.set(self.ip_key, 2, 900)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get(self.ip_key), 3)

    def test_reset_requests_use_their_own_volume_bucket(self) -> None:
        for _ in range(10):
            response = self.client.post(reverse("users:password_reset"), {"email": "x@example.com"})
            self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
        self.assertEqual(cache.get(self.volume_key), 10)

        response = self.client.post(reverse("users:password_reset"), {"email": "x@example.com"})
        self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
        self.assertIn(
            "Too many authentication attempts",
            " ".join(str(message) for message in get_messages(response.wsgi_request)),
        )
        self.assertIsNone(cache.get(self.ip_key))
        self.assertIsNone(cache.get("auth_account_attempts_x@example.com"))
        self.assertEqual(cache.get(self.volume_key), 11)

    def test_login_body_carries_client_ip(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            self.client.post(reverse("users:login"), self.credentials)
            platform.authenticate_customer.assert_called_with(
                self.email, self.credentials["password"], client_ip="127.0.0.1"
            )
            self.client.post(reverse("users:login"), {**self.credentials, "mfa_token": "123456"})
            platform.authenticate_customer.assert_called_with(
                self.email, self.credentials["password"], mfa_token="123456", client_ip="127.0.0.1"
            )

    def test_falsy_valid_response_counts_as_failure(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = {"valid": False}
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get(self.ip_key), 1)
        self.assertEqual(cache.get(self.account_key), 1)

    def test_upstream_throttle_counts_as_failure(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.side_effect = PlatformAPIError(
                "Too many requests", status_code=429, retry_after=30
            )
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertContains(response, "Too many login attempts")
        self.assertEqual(cache.get(self.ip_key), 1)
        self.assertEqual(cache.get(self.account_key), 1)

    def test_service_error_preserves_counters(self) -> None:
        cache.set(self.ip_key, 2, 900)
        cache.set(self.account_key, 2, 1800)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.side_effect = PlatformAPIError("unavailable", status_code=503)
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get(self.ip_key), 2)
        self.assertEqual(cache.get(self.account_key), 2)

    def test_volume_paths_ignore_login_limits_and_count_invalid_forms(self) -> None:
        cache.set(self.ip_key, 5, 900)
        cache.set(self.account_key, 5, 1800)
        for name in ("users:password_reset", "users:register"):
            response = self.client.post(reverse(name), {"email": self.email})
            self.assertEqual(response.status_code, 302 if name == "users:password_reset" else 200)
        self.assertEqual(cache.get(self.volume_key), 2)
        self.assertEqual(cache.get(self.ip_key), 5)
        self.assertEqual(cache.get(self.account_key), 5)

    def test_volume_limit_does_not_block_login(self) -> None:
        cache.set(self.volume_key, 10, 900)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get(self.ip_key), 1)
        self.assertEqual(cache.get(self.volume_key), 10)

    def test_client_ip_is_normalized_in_signed_request_body(self) -> None:
        response = Response()
        response.status_code = 200
        response._content = b'{"success": false}'
        with patch("apps.api_client.services.portal_request", return_value=response) as transport:
            client = PlatformAPIClient()
            for address, expected in (("127.0.0.1", "127.0.0.1"), ("2001:0db8::1", "2001:db8::1")):
                with self.subTest(address=address):
                    client.authenticate_customer(self.email, "test-password", client_ip=address)
                    body = json.loads(transport.call_args.kwargs["data"])
                    self.assertEqual(body["client_ip"], expected)

    def test_invalid_client_ip_is_omitted_from_request_body(self) -> None:
        response = Response()
        response.status_code = 200
        response._content = b'{"success": false}'
        with patch("apps.api_client.services.portal_request", return_value=response) as transport:
            client = PlatformAPIClient()
            for address in ("", "invalid", "127.0.0.1, 192.0.2.1"):
                with self.subTest(address=address):
                    client.authenticate_customer(self.email, "test-password", client_ip=address)
                    body = json.loads(transport.call_args.kwargs["data"])
                    self.assertNotIn("client_ip", body)
                    self.assertEqual(body["email"], self.email)
