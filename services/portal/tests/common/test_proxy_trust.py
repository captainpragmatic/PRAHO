"""Proxy trust must preserve independent customer authentication budgets."""

import importlib.util
import json
import os
from unittest.mock import patch

from django.core.cache import cache
from django.core.checks import Error, Tags, run_checks
from django.core.checks import Warning as CheckWarning
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from requests import Response


@override_settings(
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=[],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-proxy-trust-tests",
        }
    },
)
class ProxyTrustTests(SimpleTestCase):
    def setUp(self) -> None:
        # conftest.py forces settings.DEBUG = True before every test, after a class-level
        # override has been applied; enabling this one here runs after that fixture.
        debug_off = override_settings(DEBUG=False)
        debug_off.enable()
        self.addCleanup(debug_off.disable)
        cache.clear()
        self.addCleanup(cache.clear)
        upstream = Response()
        upstream.status_code = 200
        upstream._content = b'{"success": false}'
        transport = patch("apps.api_client.services.portal_request", return_value=upstream)
        self.transport = transport.start()
        self.addCleanup(transport.stop)

    def test_indistinguishable_clients_skip_ip_but_keep_account_limits(self) -> None:
        email = "one@example.com"
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            for _ in range(5):
                response = self.client.post("/login/", {"email": email, "password": "wrong"})
                self.assertEqual(response.status_code, 200)
            self.assertIsNone(cache.get("auth_ip_attempts_127.0.0.1"))
            self.assertEqual(cache.get(f"auth_account_attempts_{email}"), 5)

            response = self.client.post(
                "/login/", {"email": "another@example.com", "password": "wrong"}, HTTP_HX_REQUEST="true"
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(cache.get("auth_account_attempts_another@example.com"), 1)
            self.assertIsNone(cache.get("auth_ip_attempts_127.0.0.1"))

            response = self.client.post(
                "/login/", {"email": email, "password": "wrong"}, HTTP_HX_REQUEST="true"
            )
            self.assertEqual(response.status_code, 429)
            self.assertIn("Account temporarily locked", response.json()["error"])
            self.assertEqual(cache.get(f"auth_account_attempts_{email}"), 5)

    def test_indistinguishable_clients_skip_volume_limits(self) -> None:
        for _ in range(11):
            response = self.client.post(reverse("users:register"), {}, HTTP_HX_REQUEST="true")
            self.assertEqual(response.status_code, 200)
        self.assertIsNone(cache.get("auth_volume_ip_127.0.0.1"))
        self.assertIsNone(cache.get("auth_ip_attempts_127.0.0.1"))

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=["10.0.0.0/8"])
    def test_trusted_proxy_uses_forwarded_ip_for_login_bucket(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = None
            response = self.client.post(
                "/login/",
                {"email": "forwarded@example.com", "password": "wrong"},
                REMOTE_ADDR="10.0.0.5",
                HTTP_X_FORWARDED_FOR="203.0.113.7",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get("auth_ip_attempts_203.0.113.7"), 1)
        self.assertIsNone(cache.get("auth_ip_attempts_10.0.0.5"))

    def test_signed_login_omits_indistinguishable_ip(self) -> None:
        response = self.client.post(
            "/login/",
            {"email": "body@example.com", "password": "wrong"},
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.7",
        )
        self.assertEqual(response.status_code, 200)
        calls = [
            call for call in self.transport.call_args_list if call.kwargs["url"].endswith("/users/login/")
        ]
        self.assertTrue(calls)
        for call in calls:
            body = json.loads(call.kwargs["data"])
            self.assertNotIn("client_ip", body)
            self.assertEqual(body["email"], "body@example.com")

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=["10.0.0.0/8"])
    def test_signed_login_carries_forwarded_ip(self) -> None:
        response = self.client.post(
            "/login/",
            {"email": "body@example.com", "password": "wrong"},
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.7",
        )
        self.assertEqual(response.status_code, 200)
        calls = [
            call for call in self.transport.call_args_list if call.kwargs["url"].endswith("/users/login/")
        ]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual(json.loads(call.kwargs["data"])["client_ip"], "203.0.113.7")

    def test_deployment_check_requires_proxy_trust(self) -> None:
        issues = run_checks(tags=[Tags.security], include_deployment_checks=True)
        matches = [issue for issue in issues if issue.id == "portal.E001"]
        self.assertTrue(matches)
        self.assertTrue(all(isinstance(issue, Error) for issue in matches))

    @override_settings(DEBUG=True)
    def test_debug_deployment_check_warns_about_proxy_trust(self) -> None:
        issues = run_checks(tags=[Tags.security], include_deployment_checks=True)
        matches = [issue for issue in issues if issue.id == "portal.W001"]
        self.assertTrue(matches)
        self.assertTrue(all(isinstance(issue, CheckWarning) for issue in matches))

    def test_prod_settings_refuse_import_without_proxy_trust(self) -> None:
        env = {
            "PORTAL_TRUSTED_PROXY_CIDRS": "",
            "DJANGO_SECRET_KEY": "logging-config-tests-only-key-xxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "PLATFORM_API_SECRET": "dGVzdC1zZWNyZXQtZm9yLWxvZ2dpbmctY29uZmlnLXRlc3Rz",
            "PLATFORM_API_ALLOW_INSECURE_HTTP": "true",
            "ALLOWED_HOSTS": "portal.pragmatichost.com",
            "PORTAL_DOMAIN": "portal.pragmatichost.com",
            "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "test-webhook-secret-for-logging-config-tests",
        }
        spec = importlib.util.find_spec("config.settings.prod")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with (
            patch.dict(os.environ, env, clear=False),
            patch("config.settings.base.IPWARE_TRUSTED_PROXY_LIST", []),
            self.assertRaisesMessage(ImproperlyConfigured, "PORTAL_TRUSTED_PROXY_CIDRS"),
        ):
            spec.loader.exec_module(module)

    def test_base_settings_parse_proxy_cidrs_from_environment(self) -> None:
        spec = importlib.util.find_spec("config.settings.base")
        assert spec is not None and spec.loader is not None
        for raw, expected in (
            ("", []),
            (" , ", []),
            (" 10.0.0.0/8, ,127.0.0.1/32, ::1/128 ", ["10.0.0.0/8", "127.0.0.1/32", "::1/128"]),
        ):
            with self.subTest(raw=raw), patch.dict(os.environ, {"PORTAL_TRUSTED_PROXY_CIDRS": raw}):
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertEqual(module.IPWARE_TRUSTED_PROXY_LIST, expected)
