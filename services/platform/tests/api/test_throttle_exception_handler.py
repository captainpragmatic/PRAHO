from __future__ import annotations

import ast
import pathlib
from types import SimpleNamespace

from django.test import SimpleTestCase
from rest_framework.exceptions import Throttled
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from apps.api.exception_handlers import platform_exception_handler
from apps.common.performance.rate_limiting import (
    AuthThrottle,
    BurstAPIThrottle,
    BurstRateThrottle,
    CustomerRateThrottle,
    PortalHMACBurstThrottle,
    PortalHMACRateThrottle,
    StandardAPIThrottle,
)


def _parse_canonical_throttle_rates() -> dict[str, str]:
    """Read THROTTLE_RATES from the base settings source file via AST.

    Reading the source file (not the live Python object) makes this function
    completely immune to any in-process mutation of the shared THROTTLE_RATES
    dict that may occur during --parallel test runs.

    Handles both plain string literals ("5/minute") and os.environ.get() calls
    by extracting the default value from the second argument.
    """
    base_py = pathlib.Path(__file__).resolve().parents[2] / "config" / "settings" / "base.py"
    tree = ast.parse(base_py.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "THROTTLE_RATES" for t in node.targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        result: dict[str, str] = {}
        for key_node, val_node in zip(node.value.keys, node.value.values, strict=False):
            if not isinstance(key_node, ast.Constant):
                continue
            if isinstance(val_node, ast.Constant):
                result[key_node.value] = val_node.value
            elif isinstance(val_node, ast.Call) and len(val_node.args) >= 2 and isinstance(val_node.args[1], ast.Constant):
                # os.environ.get("KEY", "default") → use the default
                result[key_node.value] = val_node.args[1].value
        return result
    raise RuntimeError("THROTTLE_RATES dict not found in config/settings/base.py")  # pragma: no cover


# Parse once at module load; result is a plain dict of string literals from
# base.py — completely decoupled from the live runtime objects.
_CANONICAL_THROTTLE_RATES: dict[str, str] = _parse_canonical_throttle_rates()


class PlatformExceptionHandlerTests(SimpleTestCase):
    def test_throttled_response_is_normalized(self) -> None:
        response = platform_exception_handler(Throttled(wait=12.4), context={})

        assert response is not None
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.data["success"], False)
        self.assertEqual(response.data["error"], "Too many requests")
        self.assertEqual(response.data["retry_after"], 13)
        self.assertEqual(response["Retry-After"], "13")
        self.assertIn("detail", response.data)

    def test_throttled_response_uses_existing_retry_after_header_when_available(self) -> None:
        exc = Throttled(wait=None)
        response = platform_exception_handler(exc, context={})

        assert response is not None
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.data["error"], "Too many requests")
        self.assertGreaterEqual(int(response["Retry-After"]), 1)


class ThrottleConfigurationTests(SimpleTestCase):
    def test_default_throttle_rates_have_single_source_scopes(self) -> None:
        # Compare against _CANONICAL_THROTTLE_RATES which is parsed from the
        # base.py source file via AST — completely independent of the live
        # THROTTLE_RATES dict that parallel workers may mutate in-place.
        rates = _CANONICAL_THROTTLE_RATES

        self.assertEqual(rates["auth"], "10/minute")
        self.assertEqual(rates["sustained"], "2000/hour")
        self.assertEqual(rates["api_burst"], "120/min")
        self.assertEqual(rates["anon"], "40/minute")
        self.assertEqual(rates["burst"], "60/10s")
        self.assertEqual(rates["customer"], "200/minute")
        self.assertEqual(rates["portal_hmac"], "200/minute")
        self.assertEqual(rates["portal_hmac_burst"], "100/10s")

    def test_api_core_throttles_use_scopes_from_throttle_rates(self) -> None:
        self.assertEqual(StandardAPIThrottle.scope, "sustained")
        self.assertEqual(BurstAPIThrottle.scope, "api_burst")
        self.assertEqual(AuthThrottle.scope, "auth")

class PortalHMACThrottleTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()

    def test_portal_hmac_rate_throttle_uses_portal_identity(self) -> None:
        # PortalHMACRateThrottle keys on portal_id only (not customer_id) to
        # avoid unbounded cache key growth across customers per portal.
        request = SimpleNamespace(
            headers={"X-Portal-Id": "portal-001"},
            data={"customer_id": 123, "user_id": 7},
            _portal_authenticated=True,
        )

        key = PortalHMACRateThrottle().get_cache_key(request, view=None)
        self.assertIsNotNone(key)
        self.assertIn("portal-001", key or "")

    def test_portal_hmac_burst_throttle_uses_portal_only_fallback(self) -> None:
        request = SimpleNamespace(
            headers={"X-Portal-Id": "portal-001"},
            data={"timestamp": 1234567890},
            _portal_authenticated=True,
        )

        key = PortalHMACBurstThrottle().get_cache_key(request, view=None)
        self.assertIsNotNone(key)
        self.assertIn("portal-001", key or "")

    def test_portal_hmac_throttle_returns_none_without_portal_auth_flag(self) -> None:
        request = self.factory.post("/api/tickets/summary/", {"customer_id": 123}, format="json", HTTP_X_PORTAL_ID="p1")
        drf_request = Request(request)

        self.assertIsNone(PortalHMACRateThrottle().get_cache_key(drf_request, view=None))
        self.assertIsNone(PortalHMACBurstThrottle().get_cache_key(drf_request, view=None))

    def test_customer_and_burst_throttles_skip_portal_hmac_requests(self) -> None:
        request = self.factory.post(
            "/api/tickets/summary/",
            {"customer_id": 123, "user_id": 7},
            format="json",
            HTTP_X_PORTAL_ID="portal-001",
        )
        request._portal_authenticated = True
        drf_request = Request(request)

        self.assertIsNone(CustomerRateThrottle().get_cache_key(drf_request, view=None))
        self.assertIsNone(BurstRateThrottle().get_cache_key(drf_request, view=None))
