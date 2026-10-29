"""A portal session is bound to the browser that signed in, not to its network address.

The binding is the browser family and the operating system, without version numbers: a browser
update keeps the session, another browser or another operating system ends it. A new network (mobile
data to Wi-Fi) keeps it. Login stamps the binding, so a session without one ends instead of being
bound to whichever browser presents the cookie first (ADR-0017 section 5).
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.common.browser_identity import browser_identity
from apps.common.middleware import SessionSecurityMiddleware
from tests.helpers.platform_login import session_fields

CHROME_130_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)
CHROME_131_MAC = CHROME_130_MAC.replace("Chrome/130.0.0.0", "Chrome/131.0.6778.86")
FIREFOX_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0"
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
SESSION_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "binding"}},
}


class BrowserIdentityTests(TestCase):
    def test_the_identity_is_the_family_and_the_system_without_versions(self) -> None:
        cases = {
            CHROME_130_MAC: "chrome/macos",
            CHROME_131_MAC: "chrome/macos",
            FIREFOX_MAC: "firefox/macos",
            CHROME_WINDOWS: "chrome/windows",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.68": "edge/windows",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36 OPR/114.0.0.0": "opera/windows",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Safari/605.1.15": "safari/macos",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Mobile/15E148 Safari/604.1": "safari/ios",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1": "chrome/ios",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Mobile Safari/537.36": "chrome/android",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0": "firefox/linux",
            "curl/8.4.0": "other/other",
            "": "other/other",
        }
        for user_agent, identity in cases.items():
            with self.subTest(user_agent=user_agent[:60]):
                self.assertEqual(browser_identity(user_agent), identity)


@override_settings(**SESSION_SETTINGS)
class BindingTests(TestCase):
    def setUp(self) -> None:
        # The suite's conftest turns the rule off for hand-built sessions; this is the rule's own test.
        required = override_settings(PORTAL_BROWSER_FINGERPRINT_REQUIRED=True)
        required.enable()
        self.addCleanup(required.disable)

    def request(self, user_agent: str = CHROME_130_MAC, ip: str = "203.0.113.10") -> HttpRequest:
        request = RequestFactory().get("/dashboard/", HTTP_USER_AGENT=user_agent, REMOTE_ADDR=ip)
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        request.session.update({"user_id": 42, "customer_id": 7, "last_activity": timezone.now().timestamp()})
        return request

    def signed_in(self, user_agent: str = CHROME_130_MAC) -> dict[str, object]:
        """The session data as login leaves it."""
        request = self.request(user_agent)
        SessionSecurityMiddleware.stamp_fingerprint(request.session, user_agent)
        return dict(request.session.items())

    def follow(self, data: dict[str, object], user_agent: str, ip: str = "203.0.113.10") -> tuple[bool, HttpRequest]:
        request = self.request(user_agent, ip)
        request.session.clear()
        request.session.update(data)
        ended = SessionSecurityMiddleware(lambda request: HttpResponse()).process_request(request) is not None
        return ended, request

    def test_a_browser_update_keeps_the_session_and_restamps_it(self) -> None:
        data = self.signed_in(CHROME_130_MAC)
        ended, request = self.follow(data, CHROME_131_MAC)
        self.assertFalse(ended)
        self.assertNotEqual(
            request.session["security_fingerprint"]["user_agent_hash"], data["security_fingerprint"]["user_agent_hash"]
        )

    def test_another_browser_or_system_ends_the_session(self) -> None:
        data = self.signed_in(CHROME_130_MAC)
        for other in (FIREFOX_MAC, CHROME_WINDOWS):
            with self.subTest(user_agent=other[:40]):
                ended, _request = self.follow(data, other)
                self.assertTrue(ended)

    def test_a_new_network_keeps_the_session(self) -> None:
        data = self.signed_in(CHROME_130_MAC)
        ended, _request = self.follow(data, CHROME_130_MAC, ip="198.51.100.77")
        self.assertFalse(ended)

    def test_a_session_login_did_not_stamp_ends(self) -> None:
        legacy = {"ip_hash": "a1b2c3", "user_agent_hash": "d4e5f6", "created_at": timezone.now().timestamp()}
        for name, fingerprint in {"none": None, "from before this release": legacy}.items():
            with self.subTest(fingerprint=name):
                data = {"user_id": 42, "customer_id": 7, "last_activity": timezone.now().timestamp()}
                if fingerprint is not None:
                    data["security_fingerprint"] = fingerprint
                ended, _request = self.follow(data, CHROME_130_MAC)
                self.assertTrue(ended)

    def test_the_stamp_holds_no_address(self) -> None:
        fingerprint = self.signed_in()["security_fingerprint"]
        self.assertEqual(fingerprint["browser"], "chrome/macos")
        self.assertNotIn("ip_hash", fingerprint)

    @override_settings(PORTAL_BROWSER_FINGERPRINT_REQUIRED=False)
    def test_control_without_the_rule_a_missing_stamp_is_minted(self) -> None:
        data = {"user_id": 42, "customer_id": 7, "last_activity": (timezone.now() - timedelta(seconds=5)).timestamp()}
        ended, request = self.follow(data, CHROME_130_MAC)
        self.assertFalse(ended)
        self.assertEqual(request.session["security_fingerprint"]["browser"], "chrome/macos")


@override_settings(**SESSION_SETTINGS, RATE_LIMITING_ENABLED=False)
class LoginStampTests(TestCase):
    def test_signing_in_binds_the_session_to_this_browser(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
                "session_id": "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00",
                **session_fields(),
            }
            platform.post.return_value = {"success": True, "results": [{"id": 456, "name": "Acme", "role": "owner"}]}
            platform.get_customer_profile.return_value = {"first_name": "Ana"}
            response = self.client.post(
                "/login/", {"email": "ana@example.ro", "password": "pass123"}, HTTP_USER_AGENT=CHROME_130_MAC
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["user_id"], 123)
        self.assertEqual(self.client.session["security_fingerprint"]["browser"], "chrome/macos")
