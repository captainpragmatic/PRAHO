from __future__ import annotations

import inspect
from copy import deepcopy

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils.module_loading import import_string
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

from apps.api.core import throttling as core_throttling
from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle, StandardAPIThrottle
from apps.api.customers.views import customer_users_create
from apps.api.orders.views import (
    OrderCalculateThrottle,
    OrderCreateThrottle,
    OrderListThrottle,
    ProductCatalogThrottle,
)
from apps.api.users import views as users_views
from apps.common.apps import _validate_throttle_rates_at_startup
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
            rate_limiting.PortalHMACCreateUserThrottle,
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
            "portal_hmac_create_user",
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

    def test_create_user_view_uses_portal_scoped_throttles_not_burst(self) -> None:
        """customer_users_create must key throttling on the verified portal id.

        Regression guard: the endpoint runs with authentication_classes([]), so an
        IP-keyed throttle (BurstAPIThrottle / any UserRateThrottle) is bypassable by
        distributing requests across IPs. The view must layer the per-portal HMAC
        throttles plus the strict create-user cap instead.
        """
        throttle_classes = customer_users_create.cls.throttle_classes
        self.assertIn(rate_limiting.PortalHMACCreateUserThrottle, throttle_classes)
        self.assertIn(rate_limiting.PortalHMACRateThrottle, throttle_classes)
        self.assertIn(rate_limiting.PortalHMACBurstThrottle, throttle_classes)
        self.assertNotIn(BurstAPIThrottle, throttle_classes)

    def test_create_user_throttle_is_portal_keyed_and_noops_without_portal_auth(self) -> None:
        factory = RequestFactory()
        throttle = rate_limiting.PortalHMACCreateUserThrottle()

        # No portal authentication → throttle must not engage (returns None).
        unauth = factory.post("/api/users/customers/1/users/", content_type="application/json")
        self.assertIsNone(throttle.get_cache_key(unauth, view=None))

        # Same portal, different payloads → same key (keyed on portal id, not body).
        req_a = factory.post("/api/users/customers/1/users/", content_type="application/json")
        req_b = factory.post("/api/users/customers/99999/users/", content_type="application/json")
        req_a._portal_authenticated = True  # type: ignore[attr-defined]  # test sets internal HMAC flag
        req_b._portal_authenticated = True  # type: ignore[attr-defined]  # test sets internal HMAC flag
        req_a.META["HTTP_X_PORTAL_ID"] = "portal-a"
        req_b.META["HTTP_X_PORTAL_ID"] = "portal-a"
        self.assertEqual(throttle.get_cache_key(req_a, view=None), throttle.get_cache_key(req_b, view=None))

        # Different portal → different key (no cross-portal collateral throttling).
        req_c = factory.post("/api/users/customers/1/users/", content_type="application/json")
        req_c._portal_authenticated = True  # type: ignore[attr-defined]  # test sets internal HMAC flag
        req_c.META["HTTP_X_PORTAL_ID"] = "portal-b"
        self.assertNotEqual(throttle.get_cache_key(req_a, view=None), throttle.get_cache_key(req_c, view=None))

    def test_create_user_throttle_parses_env_configurable_shorthand_rates(self) -> None:
        """THROTTLE_RATE_PORTAL_CREATE_USER must accept shorthand windows (e.g. 30/10s).

        Startup validation (parse_rate_string) accepts shorthand rates, so the
        throttle class must parse them too — otherwise an env value that passes
        the fail-fast startup check would 500 on the first request instead.
        """
        throttle = rate_limiting.PortalHMACCreateUserThrottle()
        self.assertEqual(throttle.parse_rate("30/10s"), (30, 10))

    def test_startup_validation_covers_create_user_throttle_scope(self) -> None:
        """Dropping the create-user rate must fail at startup, not at request time.

        PortalHMACCreateUserThrottle is a per-view throttle, so it is not covered
        by DEFAULT_THROTTLE_CLASSES validation — it must be explicitly registered
        in the startup validation list like the other per-view throttles.
        """
        rest_framework = deepcopy(settings.REST_FRAMEWORK)
        del rest_framework["DEFAULT_THROTTLE_RATES"]["portal_hmac_create_user"]
        with override_settings(REST_FRAMEWORK=rest_framework), self.assertRaises(ImproperlyConfigured):
            _validate_throttle_rates_at_startup()

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
