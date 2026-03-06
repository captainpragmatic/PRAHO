from __future__ import annotations

import inspect

from django.conf import settings
from django.test import RequestFactory, SimpleTestCase
from django.utils.module_loading import import_string
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

from apps.api.core import throttling as core_throttling
from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle, StandardAPIThrottle
from apps.api.orders.views import (
    OrderCalculateThrottle,
    OrderCreateThrottle,
    OrderListThrottle,
    ProductCatalogThrottle,
)
from apps.api.users import views as users_views
from apps.common.performance import rate_limiting


class ThrottleArchitectureGuardrailTests(SimpleTestCase):
    def test_default_throttle_class_paths_resolve_with_configured_scopes(self) -> None:
        rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
        for class_path in settings.REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"]:
            throttle_cls = import_string(class_path)
            self.assertTrue(issubclass(throttle_cls, SimpleRateThrottle))
            scope = getattr(throttle_cls, "scope", None)
            if scope:
                self.assertIn(scope, rates)

    def test_per_view_throttle_classes_have_scopes_in_settings(self) -> None:
        rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
        classes = [
            StandardAPIThrottle,
            BurstAPIThrottle,
            AuthThrottle,
            OrderCreateThrottle,
            OrderCalculateThrottle,
            OrderListThrottle,
            ProductCatalogThrottle,
            AnonRateThrottle,
        ]
        for throttle_cls in classes:
            scope = getattr(throttle_cls, "scope", None)
            self.assertIsNotNone(scope, f"{throttle_cls.__name__} must declare a scope")
            self.assertIn(scope, rates, f"Missing THROTTLE_RATES['{scope}']")

    def test_throttle_rates_have_no_orphan_scopes(self) -> None:
        rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
        required_scopes = {
            "portal_hmac",
            "portal_hmac_burst",
            "customer",
            "burst",
            "auth",
            "sustained",
            "api_burst",
            "anon",
            "order_create",
            "order_calculate",
            "order_list",
            "product_catalog",
        }
        self.assertEqual(set(rates.keys()), required_scopes)

    def test_users_module_uses_canonical_auth_throttle(self) -> None:
        self.assertIs(users_views.AuthThrottle, AuthThrottle)

    def test_api_core_throttling_module_has_no_hardcoded_rate_literals(self) -> None:
        source = inspect.getsource(core_throttling)
        self.assertNotIn("rate =", source)

    def test_removed_legacy_throttle_classes_stay_removed(self) -> None:
        for removed_name in (
            "SustainedRateThrottle",
            "AnonymousRateThrottle",
            "WriteOperationThrottle",
            "ServiceRateThrottle",
            "EndpointThrottle",
            "get_throttle_rate_for_endpoint",
        ):
            self.assertFalse(hasattr(rate_limiting, removed_name))

    def test_portal_hmac_throttle_key_is_stable_for_same_portal(self) -> None:
        factory = RequestFactory()
        throttle = rate_limiting.PortalHMACRateThrottle()
        request1 = factory.post("/api/users/customers/", data={"customer_id": 1}, content_type="application/json")
        request2 = factory.post("/api/users/customers/", data={"customer_id": 99999}, content_type="application/json")
        request1._portal_authenticated = True  # type: ignore[attr-defined]  # test sets internal HMAC flag
        request2._portal_authenticated = True  # type: ignore[attr-defined]  # test sets internal HMAC flag
        request1.META["HTTP_X_PORTAL_ID"] = "portal-a"
        request2.META["HTTP_X_PORTAL_ID"] = "portal-a"

        key1 = throttle.get_cache_key(request1, view=None)
        key2 = throttle.get_cache_key(request2, view=None)

        self.assertEqual(key1, key2)
