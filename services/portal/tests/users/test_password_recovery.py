"""Portal recovery submits real API contracts without owning user records."""

import time
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common import counters
from apps.users.forms import ChangePasswordForm, CustomerRegistrationForm, MFAReauthenticationForm


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=False,
)
class PasswordRecoveryViewTests(TestCase):
    link = "/password-reset/confirm/MQ/correct-token/"
    clean_link = "/password-reset/confirm/"

    def setUp(self):
        cache.clear()

    def test_request_calls_platform_before_success(self):
        with patch("apps.users.views.api_client") as api:
            api.request_password_reset.return_value = {"success": True}
            response = self.client.post("/password-reset/", {"email": "owner@example.test"})
        self.assertEqual(response.status_code, 302)
        api.request_password_reset.assert_called_once_with("owner@example.test", client_ip="127.0.0.1")

    def test_login_preserves_recovered_password_whitespace(self):
        password = " Replacement-password-529! "
        with patch("apps.users.views.api_client") as api:
            api.authenticate_customer.return_value = None
            self.client.post("/login/", {"email": "owner@example.test", "password": password})
        self.assertEqual(api.authenticate_customer.call_args.args[1], password)

    def test_request_outage_does_not_show_success(self):
        with patch("apps.users.views.api_client") as api:
            api.request_password_reset.side_effect = PlatformAPIError("unavailable", status_code=503)
            response = self.client.post("/password-reset/", {"email": "owner@example.test"})
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "you will receive password reset instructions", status_code=503)

    def test_email_link_is_scrubbed_without_consuming_token(self):
        with patch("apps.users.views.api_client") as api:
            response = self.client.get(self.link)
        self.assertRedirects(response, self.clean_link)
        api.confirm_password_reset.assert_not_called()
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", response["Cache-Control"])
        page = self.client.get(self.clean_link)
        self.assertEqual(page["Referrer-Policy"], "same-origin")
        self.assertContains(page, "new_password")
        self.assertNotContains(page, "correct-token")

    def test_confirm_preserves_password_and_uses_only_session_identity(self):
        self.client.get(self.link)
        password = " Replacement-password-529! "
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.return_value = {"success": True}
            response = self.client.post(self.clean_link, {
                "new_password": password, "confirm_password": password,
                "uid": "another-user", "token": "forged-token",
            })
        self.assertRedirects(response, "/login/")
        api.confirm_password_reset.assert_called_once_with("MQ", "correct-token", password, password, client_ip="127.0.0.1")
        self.assertFalse(self.client.session.get("user_id"))
        self.assertNotContains(self.client.get(self.clean_link), 'name="new_password"')

    def test_validation_failure_keeps_token_but_expired_link_clears_it(self):
        self.client.get(self.link)
        payload = {"new_password": "A-different-password-29!", "confirm_password": "A-different-password-29!"}
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.side_effect = PlatformAPIError(
                "weak", status_code=400, response_data={"code": "validation_failed", "errors": {"new_password": ["Too common."]}}
            )
            response = self.client.post(self.clean_link, payload)
            self.assertContains(response, "Too common.", status_code=400)
            api.confirm_password_reset.side_effect = PlatformAPIError(
                "expired", status_code=400, response_data={"code": "invalid_reset_link"}
            )
            response = self.client.post(self.clean_link, payload)
            self.assertEqual(api.confirm_password_reset.call_count, 2)
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(self.client.get(self.clean_link), 'name="new_password"')

    def test_confirmation_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.get(self.link)
        with patch("apps.users.views.api_client") as api:
            response = client.post(self.clean_link, {"new_password": "Long-password-292!", "confirm_password": "Long-password-292!"})
        self.assertEqual(response.status_code, 403)
        api.confirm_password_reset.assert_not_called()

    def test_confirmation_accepts_valid_csrf_with_same_origin(self):
        client = Client(enforce_csrf_checks=True)
        client.get(self.link, follow=True)
        password = " Replacement-password-529! "
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.return_value = {"success": True}
            response = client.post(self.clean_link, {
                "new_password": password,
                "confirm_password": password,
                "csrfmiddlewaretoken": client.cookies["csrftoken"].value,
            }, HTTP_ORIGIN="http://testserver")
        self.assertRedirects(response, "/login/")
        api.confirm_password_reset.assert_called_once_with("MQ", "correct-token", password, password, client_ip="127.0.0.1")

    def test_confirmation_rejects_null_and_cross_origin_even_with_valid_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.get(self.link, follow=True)
        password = " Replacement-password-529! "
        with patch("apps.users.views.api_client") as api:
            for origin in ("null", "https://attacker.example.test"):
                with self.subTest(origin=origin):
                    response = client.post(self.clean_link, {
                        "new_password": password,
                        "confirm_password": password,
                        "csrfmiddlewaretoken": client.cookies["csrftoken"].value,
                    }, HTTP_ORIGIN=origin)
                    self.assertEqual(response.status_code, 403)
            api.confirm_password_reset.assert_not_called()

    def test_confirmation_outage_keeps_token_for_retry(self):
        self.client.get(self.link)
        payload = {"new_password": "Another-password-582!", "confirm_password": "Another-password-582!"}
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.side_effect = PlatformAPIError("unavailable", status_code=503)
            self.assertEqual(self.client.post(self.clean_link, payload).status_code, 503)
            api.confirm_password_reset.side_effect = None
            api.confirm_password_reset.return_value = {"success": True}
            self.assertRedirects(self.client.post(self.clean_link, payload), "/login/")
            self.assertEqual(api.confirm_password_reset.call_count, 2)

    def test_confirmation_without_recovery_session_cannot_call_platform(self):
        with patch("apps.users.views.api_client") as api:
            response = self.client.post(self.clean_link, {
                "new_password": "Another-password-582!", "confirm_password": "Another-password-582!",
                "uid": "MQ", "token": "forged",
            })
        self.assertContains(response, "invalid or has expired")
        api.confirm_password_reset.assert_not_called()

    def test_request_requires_csrf_and_platform_throttle_is_visible(self):
        with patch("apps.users.views.api_client") as api:
            response = Client(enforce_csrf_checks=True).post("/password-reset/", {"email": "owner@example.test"})
            self.assertEqual(response.status_code, 403)
            api.request_password_reset.assert_not_called()
            api.request_password_reset.side_effect = PlatformAPIError("limited", status_code=429, retry_after=60)
            response = self.client.post("/password-reset/", {"email": "owner@example.test"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "60")

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_successful_reset_requests_hit_independent_limit(self):
        counters.increment("auth_ip_attempts_127.0.0.1", 1800, delta=3)
        with patch("apps.users.views.api_client") as api:
            api.request_password_reset.return_value = {"success": True}
            for _ in range(5):
                response = self.client.post("/password-reset/", {"email": "owner@example.test"})
                self.assertEqual(response.status_code, 302)
            response = self.client.post("/password-reset/", {"email": "owner@example.test"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(api.request_password_reset.call_count, 5)
        self.assertEqual(counters.peek("auth_ip_attempts_127.0.0.1"), 3)

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_email_limit_survives_ip_change_and_login_counter_clear(self):
        with patch("apps.users.views.api_client") as api:
            api.request_password_reset.return_value = {"success": True}
            for index in range(5):
                response = self.client.post("/password-reset/", {"email": "owner@example.test"}, REMOTE_ADDR=f"192.0.2.{index + 1}")
                self.assertEqual(response.status_code, 302)
            counters.reset("auth_account_attempts_owner@example.test")
            response = self.client.post("/password-reset/", {"email": "OWNER@example.test"}, REMOTE_ADDR="192.0.2.10")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(api.request_password_reset.call_count, 5)

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_ip_limit_covers_multiple_email_addresses(self):
        with patch("apps.users.views.api_client") as api:
            api.request_password_reset.return_value = {"success": True}
            for index in range(5):
                self.assertEqual(self.client.post("/password-reset/", {"email": f"owner{index}@example.test"}).status_code, 302)
            response = self.client.post("/password-reset/", {"email": "different@example.test"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(api.request_password_reset.call_count, 5)

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_confirmation_works_with_exhausted_login_counters(self):
        self.client.get(self.link)
        counters.increment("auth_ip_attempts_127.0.0.1", 1800, delta=5)
        counters.increment("auth_account_attempts_owner@example.test", 1800, delta=5)
        password = " Replacement-password-529! "
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.return_value = {"success": True}
            response = self.client.post(self.clean_link, {"new_password": password, "confirm_password": password})
        self.assertRedirects(response, "/login/")
        api.confirm_password_reset.assert_called_once_with("MQ", "correct-token", password, password, client_ip="127.0.0.1")
        self.assertEqual(counters.peek("auth_ip_attempts_127.0.0.1"), 5)
        self.assertEqual(counters.peek("auth_account_attempts_owner@example.test"), 5)

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_confirmation_limit_preserves_token_and_other_budgets(self):
        self.client.get(self.link)
        counters.increment("auth_ip_attempts_127.0.0.1", 1800, delta=3)
        payload = {"new_password": "Another-password-582!", "confirm_password": "Another-password-582!"}
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.side_effect = PlatformAPIError(
                "weak", status_code=400, response_data={"code": "validation_failed", "errors": {"new_password": ["Too common."]}}
            )
            for _ in range(5):
                self.assertEqual(self.client.post(self.clean_link, payload).status_code, 400)
            response = self.client.post(self.clean_link, payload)
            self.assertEqual(response.status_code, 429)
            self.assertEqual(api.confirm_password_reset.call_count, 5)
            self.assertEqual(response["Referrer-Policy"], "same-origin")
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(response["Retry-After"], "900")
            self.assertContains(response, 'name="new_password"', status_code=429)
            self.assertNotContains(response, "correct-token", status_code=429)
            self.assertEqual(counters.peek("auth_ip_attempts_127.0.0.1"), 3)
            api.request_password_reset.return_value = {"success": True}
            self.assertEqual(self.client.post("/password-reset/", {"email": "owner@example.test"}).status_code, 302)
            api.confirm_password_reset.side_effect = None
            api.confirm_password_reset.return_value = {"success": True}
            response = self.client.post(self.clean_link, payload, REMOTE_ADDR="192.0.2.10")
            self.assertEqual(response.status_code, 429)
            self.assertEqual(api.confirm_password_reset.call_count, 5)
            with patch("apps.common.counters.time.time", return_value=time.time() + 901):
                response = self.client.post(self.clean_link, payload)
            self.assertRedirects(response, "/login/")
            self.assertEqual(api.confirm_password_reset.call_args.args[:2], ("MQ", "correct-token"))

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_confirmation_cache_outage_preserves_recovery_session(self):
        self.client.get(self.link)
        payload = {"new_password": "Another-password-582!", "confirm_password": "Another-password-582!"}
        with patch("apps.common.rate_limiting.counters") as limiter_cache, patch("apps.users.views.api_client") as api:
            limiter_cache.increment.side_effect = OSError("cache unavailable")
            response = self.client.post(self.clean_link, payload)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response["Referrer-Policy"], "same-origin")
            self.assertIn("no-store", response["Cache-Control"])
            self.assertContains(response, 'name="new_password"', status_code=503)
            api.confirm_password_reset.assert_not_called()
        with patch("apps.users.views.api_client") as api:
            api.confirm_password_reset.return_value = {"success": True}
            self.assertRedirects(self.client.post(self.clean_link, payload), "/login/")
            self.assertEqual(api.confirm_password_reset.call_args.args[:2], ("MQ", "correct-token"))


class PasswordRecoveryClientTests(SimpleTestCase):
    def test_password_consumers_preserve_whitespace(self):
        password = " Replacement-password-529! "
        for form, fields in (
            (ChangePasswordForm(), ("current_password", "new_password", "confirm_password")),
            (MFAReauthenticationForm(), ("password",)),
            (CustomerRegistrationForm(), ("password1", "password2")),
        ):
            for name in fields:
                with self.subTest(form=type(form).__name__, field=name):
                    self.assertEqual(form.fields[name].clean(password), password)

    def test_client_uses_existing_api_paths_without_retries(self):
        client = PlatformAPIClient()
        with patch.object(client, "_make_request", return_value={"success": True}) as request:
            self.assertTrue(client.request_password_reset("owner@example.test")["success"])
            request.assert_called_once_with("POST", "/users/password/reset/", data={"email": "owner@example.test"})
            request.reset_mock()
            client.confirm_password_reset("MQ", "token", " password ", " password ")
            request.assert_called_once_with("POST", "/users/password/reset/confirm/", data={
                "uid": "MQ", "token": "token", "new_password": " password ", "new_password_confirm": " password "
            })
