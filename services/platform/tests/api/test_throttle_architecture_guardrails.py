from __future__ import annotations

import inspect
from copy import deepcopy
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils.module_loading import import_string
from rest_framework.test import APIRequestFactory
from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle, SimpleRateThrottle, UserRateThrottle
from tests.api.test_api_auth_regressions import _has_public_marker

from apps.api.core import throttling as core_throttling
from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle, StandardAPIThrottle
from apps.api.customers import views as customers_views
from apps.api.customers.views import customer_users_create, update_customer_billing_address
from apps.api.orders import views as orders_views
from apps.api.orders.views import (
    OrderCalculateThrottle,
    OrderCreateThrottle,
    OrderListThrottle,
    ProductCatalogThrottle,
    calculate_cart_totals,
    confirm_order,
    create_order,
    order_detail,
    order_list,
    preflight_order,
    product_list,
)
from apps.api.users import views as users_views
from apps.api.users.views import SessionValidationThrottle, validate_session_secure
from apps.common.apps import _validate_throttle_rates_at_startup
from apps.common.performance import rate_limiting
from config.settings.test import LOCMEM_TEST_CACHE


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
            SessionValidationThrottle,
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
            "session_validation",
        }
        self.assertEqual(set(rates.keys()), required_scopes)

    def test_function_view_endpoint_throttles_do_not_use_scoped_rate_throttle(self) -> None:
        """DRF ScopedRateThrottle ignores a subclass scope on @api_view functions."""
        for throttle_cls in (
            OrderCreateThrottle,
            OrderCalculateThrottle,
            OrderListThrottle,
            ProductCatalogThrottle,
            SessionValidationThrottle,
        ):
            self.assertFalse(
                issubclass(throttle_cls, ScopedRateThrottle),
                f"{throttle_cls.__name__} would silently no-op without view.throttle_scope",
            )

    def test_hmac_function_views_preserve_global_portal_throttles(self) -> None:
        protected_views = (
            (calculate_cart_totals, OrderCalculateThrottle),
            (preflight_order, OrderCalculateThrottle),
            (create_order, OrderCreateThrottle),
            (order_list, OrderListThrottle),
            (order_detail, OrderListThrottle),
            (confirm_order, OrderListThrottle),
            (validate_session_secure, SessionValidationThrottle),
        )
        for view, endpoint_throttle in protected_views:
            configured = view.cls.throttle_classes
            self.assertIn(rate_limiting.PortalHMACRateThrottle, configured)
            self.assertIn(rate_limiting.PortalHMACBurstThrottle, configured)
            self.assertIn(endpoint_throttle, configured)

    def test_hmac_function_views_never_use_ip_keyed_user_throttles(self) -> None:
        """#277: generic sweep — no enumeration to keep in sync.

        The #186 defect (an IP-keyed UserRateThrottle on an HMAC endpoint running
        ``authentication_classes([])``, bypassable by rotating source IPs) survived on
        update_customer_billing_address precisely because the guardrail above is a
        hand-maintained list. This walks every registered @api_view instead, so a new
        HMAC view with the wrong throttle fails here without anyone remembering to add it.
        """
        offenders: list[str] = []
        for module in (customers_views, orders_views, users_views):
            for name, obj in vars(module).items():
                view_cls = getattr(obj, "cls", None)
                if view_cls is None or not hasattr(view_cls, "throttle_classes"):
                    continue
                # Two conditions must BOTH hold for the #186/#277 defect:
                #  1. DRF authentication is disabled → request.user is AnonymousUser, so a
                #     User/Anon throttle silently degrades to IP keying.
                #  2. The endpoint is NOT marked @public_api_endpoint. On a genuinely public
                #     view (login, password reset, registration) IP keying is the CORRECT
                #     choice — there is no portal identity to key on. Only HMAC endpoints,
                #     which do have a verified portal id, are miskeyed by it.
                if list(getattr(view_cls, "authentication_classes", [1])):
                    continue
                if _has_public_marker(obj):
                    continue
                offenders.extend(
                    f"{module.__name__}.{name} -> {throttle.__name__}"
                    for throttle in view_cls.throttle_classes
                    if issubclass(throttle, UserRateThrottle | AnonRateThrottle)
                )

        self.assertEqual(
            offenders,
            [],
            "HMAC views (authentication_classes([])) must use portal-keyed throttles, "
            f"not IP-keyed User/Anon throttles: {offenders}",
        )

    def test_billing_address_view_uses_portal_scoped_throttles_not_burst(self) -> None:
        """#277: same defect as #186's create-user fix, on a view the original sweep missed.

        ``@throttle_classes`` REPLACES DEFAULT_THROTTLE_CLASSES, so the previous
        ``[BurstAPIThrottle]`` both dropped the global per-portal limits and keyed on
        client IP (UserRateThrottle + authentication_classes([]) → AnonymousUser → IP).
        """
        throttle_classes = update_customer_billing_address.cls.throttle_classes
        self.assertIn(rate_limiting.PortalHMACRateThrottle, throttle_classes)
        self.assertIn(rate_limiting.PortalHMACBurstThrottle, throttle_classes)
        self.assertNotIn(BurstAPIThrottle, throttle_classes)

    def test_billing_address_throttle_cannot_be_bypassed_by_rotating_ip(self) -> None:
        """The behavioral half of the guard above: same portal, different IPs → same bucket."""
        factory = RequestFactory()
        first = factory.post("/api/customers/billing-address/", REMOTE_ADDR="198.51.100.10")
        second = factory.post("/api/customers/billing-address/", REMOTE_ADDR="203.0.113.20")
        for req in (first, second):
            req._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
            req.META["HTTP_X_PORTAL_ID"] = "portal-stable"

        throttle = rate_limiting.PortalHMACRateThrottle()
        self.assertEqual(
            throttle.get_cache_key(first, view=None),
            throttle.get_cache_key(second, view=None),
        )

    def test_every_project_throttle_parses_its_configured_rate(self) -> None:
        """#277: the gap that let PortalHMACRateThrottle/CustomerRateThrottle rot.

        Startup validation uses the permissive parse_rate_string, but a throttle class
        without _CustomTimeRateMixin falls through to DRF's parser, which reads the window
        from ``period[0]`` only — so ``200/10s`` passes deploy checks and then raises
        KeyError on the first live request. Asserting per-CLASS (not just on the shared
        helper) is what makes that divergence visible.
        """
        shorthand = "200/10s"
        checked: list[str] = []
        for name, obj in vars(rate_limiting).items():
            if not isinstance(obj, type) or not issubclass(obj, SimpleRateThrottle):
                continue
            # Only classes DEFINED here — DRF's own AnonRateThrottle/UserRateThrottle are in
            # this namespace by import and are not ours to fix (we subclass them instead).
            if obj.__module__ != rate_limiting.__name__:
                continue
            # Skip private bases (EndpointRateThrottle included: no .scope of its own, so
            # DRF refuses to instantiate it — its concrete subclasses are covered elsewhere).
            if name.startswith("_") or getattr(obj, "scope", None) is None:
                continue
            checked.append(name)
            with self.subTest(throttle=name):
                # Unbound call: __init__ resolves .rate from settings, which is irrelevant here
                # — we are asserting the parser the class would USE, not its configured value.
                self.assertEqual(
                    obj.parse_rate(obj, shorthand),  # type: ignore[arg-type]  # unbound on purpose
                    (200, 10),
                    f"{name} cannot parse a shorthand window that startup validation accepts",
                )

        # Guard the guard: if a refactor renames/relocates these, the loop above must not
        # silently shrink to zero and keep passing.
        self.assertIn("PortalHMACRateThrottle", checked)
        self.assertIn("CustomerRateThrottle", checked)

    def test_hmac_endpoint_throttle_cannot_be_bypassed_by_rotating_ip(self) -> None:
        factory = RequestFactory()
        first = factory.post(
            "/api/orders/create/",
            REMOTE_ADDR="198.51.100.10",
            HTTP_X_PORTAL_ID="portal-stable",
        )
        second = factory.post(
            "/api/orders/create/",
            REMOTE_ADDR="203.0.113.20",
            HTTP_X_PORTAL_ID="portal-stable",
        )
        first._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
        second._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract

        throttle = OrderCreateThrottle()
        self.assertEqual(
            throttle.get_cache_key(first, view=None),
            throttle.get_cache_key(second, view=None),
        )

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

    def test_portal_hmac_throttle_prefers_middleware_verified_portal_id(self) -> None:
        request = RequestFactory().post(
            "/api/users/customers/",
            HTTP_X_PORTAL_ID="header-portal",
        )
        request._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
        request._portal_id = "verified-portal"  # type: ignore[attr-defined]  # middleware contract

        key = rate_limiting.PortalHMACRateThrottle().get_cache_key(request, view=None)

        self.assertIn("verified-portal", key or "")
        self.assertNotIn("header-portal", key or "")


@override_settings(CACHES=LOCMEM_TEST_CACHE, RATE_LIMITING_ENABLED=True)
class EndpointThrottleBehaviorTests(TestCase):
    """Prove the endpoint-specific order cap reaches the real DRF view boundary."""

    def setUp(self) -> None:
        cache.clear()
        self.factory = APIRequestFactory()

    @patch.object(OrderCreateThrottle, "rate", "2/min", create=True)
    def test_order_create_throttle_returns_429_after_configured_limit(self) -> None:
        responses = []
        for request_number in range(3):
            request = self.factory.post(
                "/api/orders/create/",
                {"request_number": request_number},
                format="json",
                HTTP_X_PORTAL_ID="portal-throttle-test",
            )
            request._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
            responses.append(create_order(request))

        self.assertNotEqual(responses[0].status_code, 429)
        self.assertNotEqual(responses[1].status_code, 429)
        self.assertEqual(responses[2].status_code, 429)

    @patch.object(ProductCatalogThrottle, "rate", "2/min", create=True)
    def test_public_product_throttle_returns_429_by_client_ip(self) -> None:
        responses = [
            product_list(
                self.factory.get(
                    "/api/orders/products/",
                    REMOTE_ADDR="198.51.100.25",
                )
            )
            for _ in range(3)
        ]

        self.assertEqual([response.status_code for response in responses], [200, 200, 429])

    @override_settings(RATE_LIMITING_ENABLED=False)
    @patch.object(OrderCreateThrottle, "rate", "1/min", create=True)
    @patch.object(rate_limiting.PortalHMACBurstThrottle, "rate", "1/min", create=True)
    @patch.object(rate_limiting.PortalHMACRateThrottle, "rate", "1/min", create=True)
    def test_disabled_rate_limiting_bypasses_explicit_hmac_throttle_stack(self) -> None:
        responses = []
        for request_number in range(2):
            request = self.factory.post(
                "/api/orders/create/",
                {"request_number": request_number},
                format="json",
                HTTP_X_PORTAL_ID="portal-disabled-throttle",
            )
            request._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
            responses.append(create_order(request))

        self.assertNotEqual(responses[0].status_code, 429)
        self.assertNotEqual(responses[1].status_code, 429)

    @override_settings(RATE_LIMITING_ENABLED=False)
    @patch.object(ProductCatalogThrottle, "rate", "1/min", create=True)
    def test_disabled_rate_limiting_bypasses_explicit_public_endpoint_throttle(self) -> None:
        responses = [
            product_list(
                self.factory.get(
                    "/api/orders/products/",
                    REMOTE_ADDR="198.51.100.25",
                )
            )
            for _ in range(2)
        ]

        self.assertEqual([response.status_code for response in responses], [200, 200])
