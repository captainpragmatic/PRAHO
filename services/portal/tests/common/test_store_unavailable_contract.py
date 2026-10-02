"""Every Portal arm that fails closed on the counter store answers with one shape (#554).

Each subTest breaks the store under exactly one arm and asserts the full JSON contract, so reverting any
single arm to its old shape turns its own row red. Browser navigations keep a notice and a redirect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.contrib.messages.storage import default_storage
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.db import OperationalError
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from requests import Response

from apps.common.rate_limiting import APIRateLimitMiddleware, AuthenticationRateLimitMiddleware, mark_auth_failure
from apps.common.store_unavailable import STORE_UNAVAILABLE_RETRY_AFTER_SECONDS, store_unavailable_message
from apps.orders.services import GDPRCompliantCartSession
from apps.orders.views import payment_success_webhook

WEBHOOK_SECRET = "store-contract-webhook-secret"
ORDER_ID = "550e8400-e29b-41d4-a716-446655440554"


def store_down() -> OperationalError:
    return OperationalError("counter store unavailable")


@override_settings(
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    PLATFORM_API_ALLOW_INSECURE_HTTP=True,
    PLATFORM_TO_PORTAL_WEBHOOK_SECRET=WEBHOOK_SECRET,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "store-contract"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class StoreUnavailableContractTests(TestCase):
    def setUp(self) -> None:
        self.enterContext(override_settings(DEBUG=False))
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))

    def platform(self, **kwargs: object) -> Response:
        """The catalog, preflight and create calls a checkout makes before it publishes its result."""
        url = str(kwargs["url"])
        body: dict[str, object]
        if "/products/" in url:
            body = {
                "slug": "shared-hosting",
                "is_active": True,
                "requires_domain": False,
                "selling_currency": "RON",
                "currency_revision": 1,
            }
        elif url.endswith("/preflight/"):
            body = {"success": True, "errors": []}
        elif url.endswith("/create/"):
            body = {"order": {"id": ORDER_ID, "order_number": "ORD-554", "status": "draft"}}
        else:
            raise AssertionError(f"Unexpected Platform request: {url}")
        response = Response()
        response.status_code = 200
        response._content = json.dumps(body).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    # --- arms ---------------------------------------------------------------------------------------

    def middleware_request(self, path: str, **headers: str) -> HttpRequest:
        request = self.factory.post(path, {"email": "contract@example.com"}, **headers)
        request.session = SessionStore()
        request.session["user_id"] = 42
        return request

    def api_limiter(self, **headers: str) -> HttpResponse:
        middleware = APIRateLimitMiddleware(lambda request: HttpResponse("allowed"))
        with patch("apps.common.counters.increment", side_effect=store_down()):
            return middleware(self.middleware_request("/order/cart/add/", **headers))

    def auth_precheck(self, **headers: str) -> HttpResponse:
        middleware = AuthenticationRateLimitMiddleware(lambda request: HttpResponse("allowed"))
        with patch("apps.common.counters.increment", side_effect=store_down()):
            return middleware(self.middleware_request("/register/", **headers))

    def auth_record(self, **headers: str) -> HttpResponse:
        def downstream(request: HttpRequest) -> HttpResponse:
            mark_auth_failure(request, "login")
            return HttpResponse("denied", status=401)

        middleware = AuthenticationRateLimitMiddleware(downstream)
        with patch("apps.common.counters.increment", side_effect=store_down()):
            return middleware(self.middleware_request("/login/", **headers))

    def password_reset(self, **headers: str) -> HttpResponse:
        middleware = AuthenticationRateLimitMiddleware(lambda request: HttpResponse("allowed"))
        request = self.middleware_request("/password-reset/", **headers)
        with patch("apps.common.counters.increment", side_effect=store_down()):
            response = middleware.process_view(request, lambda request: HttpResponse(), (), {})
        assert response is not None
        return response

    def customer_session(self, *, with_cart: bool) -> str:
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        cart = GDPRCompliantCartSession(session)
        if with_cart:
            cart.add_item("shared-hosting", 1, "monthly")
        session.save()
        return cart.get_cart_version()

    def checkout(self, failing: str, *, with_cart: bool, **headers: str) -> HttpResponse:
        version = self.customer_session(with_cart=with_cart)
        payload = {
            "cart_version": version if with_cart else "an-earlier-version",
            "agree_terms": "on",
            "payment_method": "bank_transfer",
            "idempotency_key": "store-contract",
        }
        with patch(f"apps.common.counters.{failing}", side_effect=store_down()):
            return self.client.post("/order/create/", payload, **headers)

    def checkout_replay(self, **headers: str) -> HttpResponse:
        return self.checkout("lookup", with_cart=False, **headers)

    def checkout_claim(self, **headers: str) -> HttpResponse:
        return self.checkout("claim", with_cart=True, **headers)

    def checkout_completion(self, **headers: str) -> HttpResponse:
        """The Platform order exists; only publishing it on the claim fails."""
        return self.checkout("complete", with_cart=True, **headers)

    def confirm_payment(self, **headers: str) -> HttpResponse:
        self.customer_session(with_cart=False)
        body = json.dumps({"payment_intent_id": "pi_storecontract554", "order_id": ORDER_ID})
        with patch("apps.common.counters.claim", side_effect=store_down()):
            return self.client.post("/order/confirm-payment/", body, content_type="application/json", **headers)

    def webhook(self, **headers: str) -> HttpResponse:
        body = json.dumps({"order_id": ORDER_ID, "status": "succeeded"}, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(WEBHOOK_SECRET.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        request = self.factory.post(
            "/order/payment/webhook/",
            body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE=signature,
            HTTP_X_PLATFORM_TIMESTAMP=timestamp,
            **headers,
        )
        with patch("apps.common.counters.claim", side_effect=store_down()):
            return payment_success_webhook(request)

    # --- contract -----------------------------------------------------------------------------------

    def assert_json_contract(self, response: HttpResponse) -> None:
        self.assertEqual(response.status_code, 503, (response.get("Location"), response.content))
        self.assertEqual(response["Retry-After"], str(STORE_UNAVAILABLE_RETRY_AFTER_SECONDS))
        self.assertEqual(
            json.loads(response.content),
            {
                "success": False,
                "error": store_unavailable_message(),
                "retry_after": STORE_UNAVAILABLE_RETRY_AFTER_SECONDS,
            },
        )

    def test_every_json_caller_gets_the_same_store_failure_shape(self) -> None:
        arms: dict[str, Callable[..., HttpResponse]] = {
            "api limiter": self.api_limiter,
            "auth limiter before dispatch": self.auth_precheck,
            "auth limiter after dispatch": self.auth_record,
            "password reset limiter": self.password_reset,
            "checkout replay lookup": self.checkout_replay,
            "checkout claim": self.checkout_claim,
            "checkout completion": self.checkout_completion,
        }
        for name, arm in arms.items():
            with self.subTest(arm=name):
                self.assert_json_contract(arm(HTTP_HX_REQUEST="true"))

    def test_json_only_endpoints_get_the_same_store_failure_shape(self) -> None:
        for name, arm in {"confirm payment": self.confirm_payment, "payment webhook": self.webhook}.items():
            with self.subTest(arm=name):
                self.assert_json_contract(arm())

    def test_password_reset_json_keeps_its_recovery_headers(self) -> None:
        response = self.password_reset(HTTP_HX_REQUEST="true")
        self.assertEqual(response["Referrer-Policy"], "same-origin")
        self.assertIn("no-store", response["Cache-Control"])

    def assert_browser_notice(self, response: HttpResponse) -> None:
        """One arm per test: an unread notice from an earlier request would satisfy this for a later one."""
        self.assertRedirects(response, "/order/checkout/", fetch_redirect_response=False)
        notices = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertEqual(notices, [store_unavailable_message()])

    def test_browser_checkout_replay_gets_a_notice_and_the_checkout_page(self) -> None:
        self.assert_browser_notice(self.checkout_replay())

    def test_browser_checkout_claim_gets_a_notice_and_the_checkout_page(self) -> None:
        self.assert_browser_notice(self.checkout_claim())

    def test_browser_checkout_completion_gets_a_notice_and_the_checkout_page(self) -> None:
        self.assert_browser_notice(self.checkout_completion())


@override_settings(
    RATE_LIMITING_ENABLED=True,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "store-browser"}},
)
class APILimiterBrowserNavigationTests(TestCase):
    """The API limiter covers whole page trees, so a browser navigation must not be answered with JSON.

    It runs before MessageMiddleware, and every page under its paths re-enters it, so the notice has to be
    stored by the limiter itself and the redirect has to leave the limited paths.
    """

    def setUp(self) -> None:
        self.enterContext(override_settings(DEBUG=False))
        cache.clear()
        self.addCleanup(cache.clear)

    def notices_after(self, response: HttpResponse) -> list[str]:
        request = RequestFactory().get(response["Location"])
        request.COOKIES = {name: morsel.value for name, morsel in self.client.cookies.items()}
        request.session = self.client.session
        return [str(message) for message in default_storage(request)]

    def test_page_navigation_gets_a_notice_and_a_page_outside_the_limiter(self) -> None:
        for method in ("get", "post"):
            with self.subTest(method=method):
                self.client.cookies.clear()  # An unread notice from the previous method would count here.
                with patch("apps.common.counters.increment", side_effect=store_down()):
                    response = getattr(self.client, method)("/order/checkout/", HTTP_ACCEPT="text/html")
                self.assertEqual(response.status_code, 302, response.content)
                location = response["Location"]
                self.assertFalse(
                    APIRateLimitMiddleware(lambda request: HttpResponse())._is_api_endpoint(
                        RequestFactory().get(location)
                    ),
                    f"{location} is behind the same limiter and would loop",
                )
                self.assertEqual(self.notices_after(response), [store_unavailable_message()])

    def test_json_callers_still_get_the_json_contract(self) -> None:
        with patch("apps.common.counters.increment", side_effect=store_down()):
            response = self.client.get("/order/checkout/", HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)["error"], store_unavailable_message())
