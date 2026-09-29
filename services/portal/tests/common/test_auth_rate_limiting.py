"""Regression tests for Portal authentication attempt accounting."""

import json
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common import counters


@override_settings(
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "auth-rate-limit-tests",
        }
    },
)
class AuthenticationRateLimitTests(TestCase):
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

            self.assertEqual(counters.peek(self.ip_key), 5)
            self.assertEqual(counters.peek(self.account_key), 5)
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
            self.assertEqual(counters.peek(self.ip_key), 5)
            self.assertEqual(counters.peek(self.account_key), 5)

    def test_successful_login_clears_counters(self) -> None:
        counters.increment(self.ip_key, 900, delta=3)
        counters.increment(self.account_key, 1800, delta=3)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(counters.peek(self.ip_key), 4)
            self.assertEqual(counters.peek(self.account_key), 4)

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
        self.assertEqual(counters.peek(self.ip_key), 0)
        self.assertEqual(counters.peek(self.account_key), 0)

    def test_failed_login_does_not_clear_existing_counter(self) -> None:
        counters.increment(self.ip_key, 900, delta=2)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(counters.peek(self.ip_key), 3)

    def test_reset_requests_use_their_own_volume_bucket(self) -> None:
        with patch("apps.users.views.api_client.request_password_reset", return_value={"success": True}) as reset:
            for _ in range(5):
                response = self.client.post(reverse("users:password_reset"), {"email": "x@example.com"})
                self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
            self.assertEqual(counters.peek("password_reset_ip_127.0.0.1"), 5)
            response = self.client.post(reverse("users:password_reset"), {"email": "x@example.com"})
            self.assertContains(response, "Too many password reset requests", status_code=429)
            self.assertEqual(response["Retry-After"], "900")
            self.assertEqual(reset.call_count, 5)
        self.assertEqual(counters.peek(self.ip_key), 0)
        self.assertEqual(counters.peek("auth_account_attempts_x@example.com"), 0)
        self.assertEqual(counters.peek(self.volume_key), 0)

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
        self.assertEqual(counters.peek(self.ip_key), 1)
        self.assertEqual(counters.peek(self.account_key), 1)

    def test_upstream_throttle_counts_as_failure(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.side_effect = PlatformAPIError(
                "Too many requests", status_code=429, retry_after=30
            )
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertContains(response, "Too many login attempts")
        self.assertEqual(counters.peek(self.ip_key), 1)
        self.assertEqual(counters.peek(self.account_key), 1)

    def test_service_error_preserves_counters(self) -> None:
        counters.increment(self.ip_key, 900, delta=2)
        counters.increment(self.account_key, 1800, delta=2)
        upstream = Response()
        upstream.status_code = 503
        upstream._content = b'{"error": "Service unavailable"}'
        upstream.headers["Content-Type"] = "application/json"
        upstream.headers["Retry-After"] = "0"
        with patch("apps.api_client.services.portal_request", return_value=upstream):
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertContains(response, "Authentication service is temporarily unavailable")
        self.assertEqual(counters.peek(self.ip_key), 2)
        self.assertEqual(counters.peek(self.account_key), 2)

    def test_connection_error_preserves_counters(self) -> None:
        counters.increment(self.ip_key, 900, delta=2)
        counters.increment(self.account_key, 1800, delta=2)
        with patch(
            "apps.api_client.services.portal_request",
            side_effect=RequestsConnectionError("Connection refused"),
        ):
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertContains(response, "Authentication service is temporarily unavailable")
        self.assertEqual(counters.peek(self.ip_key), 2)
        self.assertEqual(counters.peek(self.account_key), 2)

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
            "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",
        ]
    )
    def test_rejected_totp_codes_use_the_user_budget(self) -> None:
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": self.email})
        session.save()
        key = "auth_reauth_user_42"
        with patch("apps.users.views.api_client") as platform:
            platform.verify_totp_mfa.return_value = None
            for _ in range(5):
                response = self.client.post(reverse("users:mfa_setup_totp"), {"token": "123456"})
                self.assertRedirects(response, reverse("users:mfa_setup_totp"), fetch_redirect_response=False)
            self.assertEqual(counters.peek(key), 5)
            self.assertEqual(counters.peek(self.ip_key), 0)
            self.assertEqual(counters.peek(self.account_key), 0)
            response = self.client.post(
                reverse("users:mfa_setup_totp"), {"token": "123456"}, HTTP_HX_REQUEST="true"
            )
            self.assertEqual(response.status_code, 429)
            self.assertEqual(counters.peek(key), 5)
            self.assertEqual(counters.peek(self.ip_key), 0)

            response = self.client.get(reverse("users:mfa_disable"))
            self.assertEqual(response.status_code, 200)

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
            "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",
        ]
    )
    def test_mfa_reauthentication_views_share_the_user_budget(self) -> None:
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": self.email})
        session.save()
        with patch("apps.users.views.api_client") as platform:
            platform.get_customer_profile.return_value = {"mfa_enabled": True, "backup_codes_count": 3}
            platform.disable_mfa.side_effect = PlatformAPIError("Invalid credentials", status_code=401)
            platform.regenerate_backup_codes.side_effect = PlatformAPIError("Invalid credentials", status_code=401)
            for name in ("users:mfa_disable", "users:mfa_backup_codes"):
                response = self.client.post(
                    reverse(name), {"password": "test-password", "token": "123456"}
                )
                self.assertEqual(response.status_code, 200)
            self.assertEqual(counters.peek("auth_reauth_user_42"), 2)
            self.assertEqual(counters.peek(self.ip_key), 0)
            self.assertEqual(counters.peek(self.account_key), 0)

    @override_settings(
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
            "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",
        ]
    )
    def test_denied_switch_preserves_all_authentication_buckets(self) -> None:
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": self.email})
        session.save()
        expected = {
            self.ip_key: 2,
            self.account_key: 2,
            self.volume_key: 2,
            "auth_reauth_user_42": 2,
        }
        for key, count in expected.items():
            counters.increment(key, 900, delta=count)
        with patch("apps.users.views.api_client") as platform:
            for result in ({"success": False}, {"success": True, "data": {"has_access": False}}):
                with self.subTest(result=result):
                    platform.post.return_value = result
                    response = self.client.post(
                        reverse("users:switch_customer"), {"customer_id": 99, "email": self.email}
                    )
                    self.assertRedirects(response, "/profile/", fetch_redirect_response=False)
                    self.assertEqual(self.client.session["customer_id"], 7)
                    self.assertEqual({key: counters.peek(key) for key in expected}, expected)

    def test_volume_paths_ignore_login_limits_and_count_invalid_forms(self) -> None:
        counters.increment(self.ip_key, 900, delta=5)
        counters.increment(self.account_key, 1800, delta=5)
        for name in ("users:password_reset", "users:register"):
            response = self.client.post(reverse(name), {"email": "not-an-email"})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(counters.peek(self.volume_key), 1)
        self.assertEqual(counters.peek("password_reset_ip_127.0.0.1"), 1)
        self.assertEqual(counters.peek(self.ip_key), 5)
        self.assertEqual(counters.peek(self.account_key), 5)

    def test_volume_limit_does_not_block_login(self) -> None:
        counters.increment(self.volume_key, 900, delta=10)
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(reverse("users:login"), self.credentials)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(counters.peek(self.ip_key), 1)
        self.assertEqual(counters.peek(self.volume_key), 10)

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
