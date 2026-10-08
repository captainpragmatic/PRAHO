"""Effects of runtime Virtualmin connection settings at the HTTP boundary."""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Retriability
from apps.provisioning.virtualmin_auth_manager import (
    CACHE_AUTH_METHOD_PREFIX,
    AuthMethod,
    VirtualminAuthenticationManager,
)
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway, VirtualminRateLimitedError
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService

LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


def response(status: int = 200) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = b'{"status": "success", "message": "settings effect"}'
    result._content_consumed = True
    return result


@override_settings(CACHES=LOCMEM_CACHE, VIRTUALMIN_TIMEOUTS={})
class VirtualminConnectionSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.server = VirtualminServer.objects.create(
            name="connection-settings", hostname="connection.example.test", status="active", api_username="acl-user"
        )
        self.server.set_api_password("acl-password")
        self.server.save(update_fields=["encrypted_api_password"])
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))

    def set_value(self, key: str, value: int | bool) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_request_timeout_changes_dispatch_and_preserves_explicit_overrides(self) -> None:
        timeouts: list[float] = []

        def transport(method: str, url: str, *, policy: OutboundPolicy, **kwargs: object) -> requests.Response:
            timeouts.append(policy.timeout_seconds)
            return response()

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            self.set_value("virtualmin.request_timeout_seconds", 7)
            first = self.gateway._execute_http_request({"program": "info"}, auth=("acl-user", "acl-password"))
            self.assertEqual(timeouts, [7.0])
            self.assertEqual(first.json()["message"], "settings effect")
            self.set_value("virtualmin.request_timeout_seconds", 9)
            self.gateway._execute_http_request({"program": "info"}, auth=("acl-user", "acl-password"))
            self.gateway._execute_http_request(
                {"program": "info"}, auth=("acl-user", "acl-password"), timeout_seconds=11
            )
            with override_settings(VIRTUALMIN_TIMEOUTS={"API_REQUEST_TIMEOUT": 13}):
                self.gateway._execute_http_request({"program": "info"}, auth=("acl-user", "acl-password"))
        self.assertEqual(timeouts, [7.0, 9.0, 11.0, 13.0])

    def test_max_retries_changes_recovery_without_replaying_ambiguous_mutations(self) -> None:
        self.set_value("virtualmin.max_retries", 1)
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[requests.exceptions.ConnectTimeout("fixture"), response()],
        ):
            result = self.gateway.call("info")
        self.assertTrue(result.is_err(), result)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
        self.assertIn("Connection timeout", str(result.unwrap_err()))

        self.set_value("virtualmin.max_retries", 2)
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[requests.exceptions.ConnectTimeout("fixture"), response()],
        ):
            recovered = self.gateway.call("info")
        self.assertTrue(recovered.is_ok(), recovered)
        self.assertEqual(recovered.unwrap().data["message"], "settings effect")
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[requests.exceptions.ReadTimeout("fixture"), response()],
        ):
            mutation = self.gateway.call("delete-domain", {"domain": "hosted.example.test"})
        self.assertTrue(mutation.is_err(), mutation)
        self.assertEqual(mutation.retriability, Retriability.UNKNOWN)

    def test_rate_limit_qps_refuses_then_permits_after_a_runtime_edit(self) -> None:
        sent: list[str] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(url)
            return response()

        self.set_value("virtualmin.rate_limit_qps", 0)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            with self.assertRaises(VirtualminRateLimitedError):
                self.gateway._execute_http_request({"program": "info"}, auth=("acl-user", "acl-password"))
            self.assertEqual(sent, [])
            self.set_value("virtualmin.rate_limit_qps", 1)
            permitted = self.gateway._execute_http_request({"program": "info"}, auth=("acl-user", "acl-password"))
        self.assertEqual(permitted.json()["message"], "settings effect")
        self.assertEqual(sent, [self.server.api_url])

    def test_hourly_limit_refuses_at_the_limit_and_keeps_operation_scopes(self) -> None:
        sent: list[str] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, str]", kwargs["params"])
            sent.append(params["program"])
            return response()

        self.set_value("virtualmin.rate_limit_max_calls_per_hour", 1)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            first = self.gateway.call("info")
            self.assertTrue(first.is_ok(), first)
            denied = self.gateway.call("info")
            self.assertTrue(denied.is_err(), denied)
            self.assertIsInstance(denied.unwrap_err(), VirtualminRateLimitedError)
            self.assertEqual(sent, ["info"])
            independent = self.gateway.call("list-domains")
            self.assertTrue(independent.is_ok(), independent)
            self.set_value("virtualmin.rate_limit_max_calls_per_hour", 2)
            permitted = self.gateway.call("info")
        self.assertTrue(permitted.is_ok(), permitted)
        self.assertEqual(permitted.unwrap().data["message"], "settings effect")
        self.assertEqual(sent, ["info", "list-domains", "info"])

    @override_settings(VIRTUALMIN_MASTER_USERNAME="master-user", VIRTUALMIN_MASTER_PASSWORD="master-password")
    def test_auth_fallback_disabled_refuses_master_even_when_it_was_cached(self) -> None:
        sent: list[tuple[str, str]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            auth = cast("tuple[str, str]", kwargs["auth"])
            sent.append(auth)
            return response(401 if auth[0] == "acl-user" else 200)

        manager = VirtualminAuthenticationManager(self.server)
        key = f"{CACHE_AUTH_METHOD_PREFIX}{self.server.pk}"
        self.set_value("virtualmin.auth_fallback_enabled", False)
        cache.set(key, AuthMethod.MASTER_PROXY.value, 3600)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            denied = manager.execute_virtualmin_command("list-domains", {})
            self.assertTrue(denied.is_err(), denied)
            self.assertEqual(sent, [("acl-user", "acl-password")])
            self.assertIn("Authentication failed", str(denied.unwrap_err()))
            self.set_value("virtualmin.auth_fallback_enabled", True)
            permitted = manager.execute_virtualmin_command("list-domains", {})
        self.assertTrue(permitted.is_ok(), permitted)
        self.assertEqual(permitted.unwrap().data["message"], "settings effect")
        self.assertEqual(sent, [("acl-user", "acl-password"), ("master-user", "master-password")])
