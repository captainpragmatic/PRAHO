"""Signed login limits and the default account lockout ladder."""

import json
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common import counters
from apps.common.models import Counter
from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "login-client-ip-limits",
        }
    },
)
class LoginClientIPLimitsTests(HMACTestMixin, TestCase):
    password = "Login-limit-secure123!"
    login_path = "/api/users/login/"
    client_ip = "203.0.113.10"

    def setUp(self) -> None:
        clock = patch("apps.common.performance.rate_limiting.time.time", return_value=1_800_000_001.0)
        clock.start()
        self.addCleanup(clock.stop)
        cache.clear()
        self.addCleanup(cache.clear)
        self.login_cache_key = f"login_ip:{self.client_ip}:30000000"
        self.users: list[User] = [
            User.objects.create_user(email=f"login-limit-{index}@example.com", password=self.password)
            for index in range(12)
        ]
        self.user = self.users[0]

    def exhaust_client_limit(self) -> None:
        for user in self.users[:10]:
            response = self.portal_post(
                self.login_path, {"email": user.email, "password": "wrong", "client_ip": self.client_ip}
            )
            self.assertEqual(response.status_code, 401, response.content)

    def test_eleventh_failure_from_one_client_ip_is_throttled(self) -> None:
        self.exhaust_client_limit()
        response = self.portal_post(
            self.login_path, {"email": self.users[10].email, "password": "wrong", "client_ip": self.client_ip}
        )
        self.assertEqual(response.status_code, 429, response.content)
        retry_after = response.json()["retry_after"]
        self.assertIsInstance(retry_after, int)
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 60)
        self.assertEqual(response["Retry-After"], str(retry_after))
        response = self.portal_post(
            self.login_path, {"email": self.users[10].email, "password": "wrong", "client_ip": "203.0.113.11"}
        )
        self.assertEqual(response.status_code, 401, response.content)

    def test_successful_logins_do_not_consume_the_client_failure_budget(self) -> None:
        for user in self.users[:11]:
            response = self.portal_post(
                self.login_path, {"email": user.email, "password": self.password, "client_ip": self.client_ip}
            )
            self.assertEqual(response.status_code, 200, response.content)
            self.assertTrue(response.json()["success"])
        self.assertEqual(counters.peek(self.login_cache_key), 0)

    def test_throttled_login_does_no_credential_work(self) -> None:
        self.exhaust_client_limit()
        self.user.refresh_from_db()
        attempts = self.user.failed_login_attempts
        self.assertEqual(attempts, 1)
        self.assertIsNone(self.user.account_locked_until)
        with patch(
            "apps.api.users.views.authenticate",
            side_effect=AssertionError("Throttled login performed credential work"),
        ):
            for password in (self.password, "wrong"):
                response = self.portal_post(
                    self.login_path, {"email": self.user.email, "password": password, "client_ip": self.client_ip}
                )
                self.assertEqual(response.status_code, 429, response.content)
                self.user.refresh_from_db()
                self.assertEqual(self.user.failed_login_attempts, attempts)
                self.assertIsNone(self.user.account_locked_until)

    def test_forged_client_ip_on_unsigned_request_is_ignored(self) -> None:
        response = self.client.post(
            self.login_path,
            json.dumps({"email": self.user.email, "password": "wrong", "client_ip": self.client_ip}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(response.json(), {"error": "HMAC authentication failed"})
        self.assertEqual(counters.peek(self.login_cache_key), 0)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_malformed_or_absent_client_ip_disables_the_per_client_limit(self) -> None:
        for forwarded_data in ({"client_ip": "not-an-ip"}, {"client_ip": 1}, {}):
            with self.subTest(forwarded_data=forwarded_data):
                for user in self.users:
                    response = self.portal_post(
                        self.login_path, {"email": user.email, "password": "wrong", **forwarded_data}
                    )
                    self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(counters.peek("login_ip:not-an-ip:30000000"), 0)
        self.assertEqual(counters.peek("login_ip:0.0.0.1:30000000"), 0)

    @override_settings(RATE_LIMITING_ENABLED=False)
    def test_kill_switch_disables_the_limit(self) -> None:
        for user in self.users:
            response = self.portal_post(
                self.login_path, {"email": user.email, "password": "wrong", "client_ip": self.client_ip}
            )
            self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(counters.peek(self.login_cache_key), 0)

        # No rate-limit counters (value NULL); each request's nonce claim is a row of its own.
        self.assertEqual(Counter.objects.filter(value__isnull=True).count(), 0)

    def test_password_reset_request_requires_hmac(self) -> None:
        path = "/api/users/password/reset/"
        response = self.client.post(path, json.dumps({"email": self.user.email}), content_type="application/json")
        self.assertEqual(response.status_code, 401, response.content)
        signed = self.portal_post(path, {"email": self.user.email, "client_ip": self.client_ip})
        self.assertNotEqual(signed.status_code, 401, signed.content)

    def test_lockout_ladder_starts_at_the_default_threshold(self) -> None:
        self.assertEqual(settings.ACCOUNT_LOCKOUT_THRESHOLD, 5)
        for attempt in range(1, 5):
            self.user.increment_failed_login_attempts()
            self.user.refresh_from_db()
            self.assertEqual(self.user.failed_login_attempts, attempt)
            self.assertIsNone(self.user.account_locked_until)
        for minutes in (5, 15):
            if minutes != 5:
                # The next failure comes once the previous lock has expired, as in a real login: a lock
                # in force is neither counted against nor extended.
                type(self.user).objects.filter(pk=self.user.pk).update(
                    account_locked_until=timezone.now() - timedelta(seconds=1)
                )
                self.user.refresh_from_db()
            before = timezone.now()
            self.user.increment_failed_login_attempts()
            self.user.refresh_from_db()
            locked_until = self.user.account_locked_until
            self.assertIsNotNone(locked_until)
            assert locked_until is not None
            self.assertLessEqual(abs((locked_until - before - timedelta(minutes=minutes)).total_seconds()), 10)

        endpoint_user = self.users[1]
        for attempt in range(1, 6):
            response = self.portal_post(self.login_path, {"email": endpoint_user.email, "password": "wrong"})
            self.assertEqual(response.status_code, 401, response.content)
            endpoint_user.refresh_from_db()
            self.assertEqual(endpoint_user.failed_login_attempts, attempt)
            if attempt < 5:
                self.assertIsNone(endpoint_user.account_locked_until)
        self.assertTrue(endpoint_user.is_account_locked())
        response = self.portal_post(self.login_path, {"email": endpoint_user.email, "password": self.password})
        self.assertEqual(response.status_code, 401, response.content)
        endpoint_user.refresh_from_db()
        self.assertEqual(endpoint_user.failed_login_attempts, 5)
