"""Production middleware contracts for shared Portal counters."""

from unittest.mock import patch

from django.apps import apps
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.db import OperationalError
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from requests import Response

from apps.api_client.services import PlatformAPIClient
from apps.common import counters
from apps.common.models import Counter
from apps.common.rate_limiting import (
    APIRateLimitMiddleware,
    AuthenticationRateLimitMiddleware,
    mark_auth_failure,
)
from apps.users.middleware import PortalAuthenticationMiddleware


@override_settings(
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-counter-sites",
        }
    },
)
class PortalCounterSiteTests(TestCase):
    def setUp(self) -> None:
        self.enterContext(override_settings(DEBUG=False))
        self.factory = RequestFactory()
        cache.clear()
        self.addCleanup(cache.clear)

    def request(self, path: str) -> HttpRequest:
        request = self.factory.post(path, {"email": "counter@example.com"}, HTTP_HX_REQUEST="true")
        request.session = SessionStore()
        request.session["user_id"] = 42
        return request

    def test_only_session_and_counter_models_are_installed(self) -> None:
        self.assertEqual({model._meta.label for model in apps.get_models()}, {"sessions.Session", "common.Counter"})

    def test_api_reserves_before_dispatch_and_counts_denied_requests(self) -> None:
        observed: list[int] = []

        def downstream(request: HttpRequest) -> HttpResponse:
            observed.append(counters.peek("api_burst_127.0.0.1"))
            return HttpResponse("allowed")

        middleware = APIRateLimitMiddleware(downstream)
        middleware.BURST_RATE_LIMIT = 2
        statuses = []
        for _ in range(3):
            cache.clear()
            statuses.append(middleware(self.request("/billing/")).status_code)
        self.assertEqual(statuses, [200, 200, 429])
        self.assertEqual(observed, [1, 2])
        self.assertEqual(counters.peek("api_burst_127.0.0.1"), 3)

    def test_cart_reserves_before_deciding(self) -> None:
        middleware = APIRateLimitMiddleware(lambda request: HttpResponse("allowed"))
        middleware.CART_SESSION_RATE_LIMIT = 2
        statuses = [middleware(self.request("/order/cart/add/")).status_code for _ in range(3)]
        self.assertEqual(statuses, [200, 200, 429])
        self.assertEqual(counters.peek("cart_session_42"), 3)

    def test_volume_reserves_before_dispatch_once_per_request(self) -> None:
        observed: list[int] = []

        def downstream(request: HttpRequest) -> HttpResponse:
            observed.append(counters.peek("auth_volume_ip_127.0.0.1"))
            return HttpResponse("allowed")

        middleware = AuthenticationRateLimitMiddleware(downstream)
        middleware.VOLUME_RATE_LIMIT = 2
        statuses = [
            middleware(self.request(path)).status_code for path in ("/register/", "/password-reset/", "/register/")
        ]
        self.assertEqual(statuses, [200, 200, 429])
        self.assertEqual(observed, [1, 2])
        self.assertEqual(counters.peek("auth_volume_ip_127.0.0.1"), 3)

    def test_api_store_failure_denies_at_each_budget(self) -> None:
        increment = counters.increment
        for failed_key in ("api_burst_127.0.0.1", "api_general_127.0.0.1", "cart_session_42"):
            with self.subTest(key=failed_key):
                Counter.objects.all().delete()

                def fail(key: str, window_seconds: int, *, delta: int = 1, failed_key: str = failed_key) -> int:
                    if key == failed_key:
                        raise OperationalError("store unavailable")
                    return increment(key, window_seconds, delta=delta)

                middleware = APIRateLimitMiddleware(lambda request: HttpResponse("allowed"))
                with patch("apps.common.counters.increment", side_effect=fail):
                    response = middleware(self.request("/order/cart/add/"))
                self.assertEqual(response.status_code, 503)

    def test_auth_store_failure_denies_volume_login_and_mfa(self) -> None:
        for path, bucket in (("/register/", "login"), ("/login/", "login"), ("/mfa/disable/", "reauth")):
            with self.subTest(path=path):

                def downstream(request: HttpRequest, bucket: str = bucket) -> HttpResponse:
                    mark_auth_failure(request, bucket)
                    return HttpResponse("denied", status=401)

                middleware = AuthenticationRateLimitMiddleware(downstream)
                with patch("apps.common.counters.increment", side_effect=OperationalError("store unavailable")):
                    response = middleware(self.request(path))
                self.assertEqual(response.status_code, 503)

    @override_settings(RATE_LIMITING_ENABLED=False)
    def test_kill_switch_leaves_store_empty(self) -> None:
        for middleware_class, path in (
            (APIRateLimitMiddleware, "/billing/"),
            (AuthenticationRateLimitMiddleware, "/register/"),
            (AuthenticationRateLimitMiddleware, "/login/"),
        ):
            response = middleware_class(lambda request: HttpResponse("allowed"))(self.request(path))
            self.assertEqual(response.status_code, 200)
        self.assertEqual(Counter.objects.count(), 0)

    def test_breaker_store_failure_denies_outage_access(self) -> None:
        request = self.request("/dashboard/")
        request.session["customer_id"] = 42
        outage = Response()
        outage.status_code = 503
        outage._content = b'{"error": "Service unavailable"}'
        outage.headers["Content-Type"] = "application/json"
        outage.headers["Retry-After"] = "0"
        with (
            override_settings(PLATFORM_API_ALLOW_INSECURE_HTTP=True),
            patch("apps.users.middleware.api_client", PlatformAPIClient()),
            patch("apps.api_client.services.portal_request", return_value=outage),
            patch("apps.common.counters.increment", side_effect=OperationalError("store unavailable")),
        ):
            response = PortalAuthenticationMiddleware(lambda request: HttpResponse("allowed"))(request)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("user_id", request.session)
