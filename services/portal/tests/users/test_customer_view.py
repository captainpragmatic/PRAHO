"""Customer view in the portal (ADR-0065): redeem the code, read only, leave."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import URLPattern, URLResolver, get_resolver, reverse
from django.utils import timezone

from apps.api_client.services import PlatformAPIError
from apps.users import customer_view_policy
from apps.users.middleware import PortalAuthenticationMiddleware

PLATFORM = "https://platform.example.test"
CODE = "A" * 43
SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
REDEEMED = {
    "session_id": SESSION_ID,
    "session_tier": "customer_view",
    "session_idle_deadline": "2026-10-28T12:10:00+00:00",
    "session_expires_at": "2026-10-28T12:30:00+00:00",
    "user": {"id": 42, "email": "owner@example.test"},
    "customer": {"id": 7, "name": "Acme", "role": "owner"},
    "staff_label": "Ana Support",
}
SETTINGS = {
    "PLATFORM_PUBLIC_ORIGIN": PLATFORM,
    "CUSTOMER_VIEW_ENABLED": True,
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cv"}},
}


@override_settings(**SETTINGS)
class RedeemTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def redeem(self, data: dict[str, str] | None = None, origin: str = PLATFORM) -> HttpResponse:
        return self.client.post(reverse("users:customer_view_redeem"), data or {"code": CODE}, HTTP_ORIGIN=origin)

    def test_a_code_from_platform_opens_the_view_in_a_fresh_session(self) -> None:
        session = self.client.session
        session.update({"user_id": 99, "portal_session_id": "own-session", "email": "staff-own@example.test"})
        session.save()
        old_key = session.session_key
        with (
            patch("apps.users.customer_view_views.api_client.redeem_customer_view", return_value=REDEEMED),
            patch("apps.users.customer_view_views.api_client.end_session") as end,
        ):
            response = self.redeem()
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response["Location"], "/dashboard/")
        end.assert_called_once_with(99, "own-session")  # the displaced session ends on Platform
        session = self.client.session
        self.assertNotEqual(session.session_key, old_key)
        self.assertEqual((session["user_id"], session["portal_session_id"]), (42, SESSION_ID))
        self.assertTrue(session["customer_view"])
        self.assertNotIn("session_auth_hash", session)
        cookie = response.cookies[self.client.cookies.keys().__iter__().__next__()]
        self.assertFalse(cookie["max-age"])  # ends with the browser

    def test_the_view_is_bound_to_the_browser_that_redeemed_it(self) -> None:
        # Otherwise the browser binding (PORTAL_BROWSER_FINGERPRINT_REQUIRED) ends it at its first page.
        chrome = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36"
        )
        with patch("apps.users.customer_view_views.api_client.redeem_customer_view", return_value=REDEEMED):
            response = self.client.post(
                reverse("users:customer_view_redeem"), {"code": CODE}, HTTP_ORIGIN=PLATFORM, HTTP_USER_AGENT=chrome
            )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.session["security_fingerprint"]["browser"], "chrome/macos")

    def test_the_code_is_exchanged_outside_the_session_this_browser_held(self) -> None:
        from apps.common import request_context  # noqa: PLC0415

        seen: dict[str, object] = {}

        def redeem(code: str, client_ip: str) -> dict[str, object]:
            seen.update(request_context.signed_fields())
            return REDEEMED

        with (
            request_context.bound(SESSION_ID, 99),  # as inside the middleware for a signed-in browser
            patch("apps.users.customer_view_views.api_client.redeem_customer_view", side_effect=redeem),
            patch("apps.users.customer_view_views.api_client.end_session"),
        ):
            self.assertEqual(self.redeem().status_code, 303)
        self.assertEqual(seen, {})

    def test_only_platform_s_page_can_hand_over_a_code(self) -> None:
        with patch("apps.users.customer_view_views.api_client.redeem_customer_view") as redeem:
            for origin in ("https://evil.example", "null", ""):
                with self.subTest(origin=origin):
                    self.assertEqual(self.redeem(origin=origin).status_code, 403)
            for data in ({"code": CODE, "extra": "1"}, {"code": "short"}, {"code": CODE + "A"}):
                with self.subTest(data=data):
                    self.assertEqual(self.redeem(data).status_code, 400)
            with override_settings(CUSTOMER_VIEW_ENABLED=False):
                self.assertEqual(self.redeem().status_code, 403)
        redeem.assert_not_called()

    def test_an_answer_carrying_a_credential_is_refused(self) -> None:
        with patch(
            "apps.users.customer_view_views.api_client.redeem_customer_view",
            return_value={**REDEEMED, "session_auth_hash": "x"},
        ):
            self.assertEqual(self.redeem().status_code, 503)
        self.assertNotIn("customer_view", self.client.session)

    def test_a_refused_code_is_a_refusal_and_an_outage_is_an_outage(self) -> None:
        for status, expected in ((403, 403), (503, 503)):
            with (
                self.subTest(status=status),
                patch(
                    "apps.users.customer_view_views.api_client.redeem_customer_view",
                    side_effect=PlatformAPIError("x", status_code=status),
                ),
            ):
                self.assertEqual(self.redeem().status_code, expected)


@override_settings(**SETTINGS)
class GateTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()

    def request(self, method: str, path: str, **extra: str) -> HttpRequest:
        request = self.factory.generic(method, path, **extra)
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        now = timezone.now()
        request.session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": "owner@example.test",
                "portal_session_id": SESSION_ID,
                "customer_view": True,
                "customer_view_customer_id": 7,
                "authenticated_at": now.isoformat(),
                "session_created_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        request.session.save()
        return request

    def through(self, request: HttpRequest) -> tuple[HttpResponse, MagicMock]:
        view = MagicMock(return_value=HttpResponse("page"))
        return PortalAuthenticationMiddleware(view)(request), view

    def test_reading_pages_are_served_and_never_cached(self) -> None:
        response, view = self.through(self.request("GET", "/dashboard/"))
        view.assert_called_once()
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_writes_are_refused_before_any_view_public_routes_included(self) -> None:
        for method, path in (
            ("POST", "/api/cookie-consent/"),
            ("POST", "/change-password/"),
            ("GET", "/change-password/"),
            ("GET", "/data-export/"),
            ("GET", f"/data-export/{uuid.uuid4()}/download/"),
            ("POST", "/tickets/create/"),
            ("POST", "/i18n/setlang/"),
            ("GET", "/order/cart/"),
            ("GET", "/no-such-page/"),
        ):
            with self.subTest(method=method, path=path):
                response, view = self.through(self.request(method, path, HTTP_HX_REQUEST="true"))
                self.assertEqual(response.status_code, 403)
                view.assert_not_called()

    def test_role_checks_fetch_memberships_without_naming_a_customer(self) -> None:
        from apps.common.decorators import _fetch_user_memberships  # noqa: PLC0415

        request = self.request("GET", "/billing/invoices/")
        with patch("apps.common.decorators.api_client.post", return_value={"success": True, "results": []}) as post:
            _fetch_user_memberships(request)
        # Platform pins a customer view to one customer; a user id sent as customer_id was refused.
        self.assertNotIn("customer_id", post.call_args.kwargs["data"])

    def test_a_query_naming_another_customer_is_refused(self) -> None:
        response, view = self.through(self.request("GET", "/billing/invoices/?customer_id=8"))
        self.assertEqual(response.status_code, 403)
        view.assert_not_called()

    def test_the_view_ends_when_the_feature_is_turned_off(self) -> None:
        request = self.request("GET", "/dashboard/")
        with override_settings(CUSTOMER_VIEW_ENABLED=False):
            response, view = self.through(request)
        self.assertEqual(response.status_code, 302)
        view.assert_not_called()
        self.assertNotIn("customer_view", request.session)

    def test_every_portal_route_is_read_only_in_a_customer_view(self) -> None:
        for name, path in _portal_routes():
            if name in customer_view_policy.CONTROLS:
                continue
            with self.subTest(route=name):
                post, view = self.through(self.request("POST", path, HTTP_HX_REQUEST="true"))
                self.assertEqual(post.status_code, 403)
                view.assert_not_called()
                if name not in customer_view_policy.READS:
                    get, view = self.through(self.request("GET", path, HTTP_HX_REQUEST="true"))
                    self.assertEqual(get.status_code, 403)
                    view.assert_not_called()


@override_settings(**SETTINGS)
class LeaveAndBannerTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        session = self.client.session
        session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "email": "owner@example.test",
                "portal_session_id": SESSION_ID,
                "customer_view": True,
                "customer_view_customer_id": 7,
                "customer_view_customer_name": "Acme",
                "customer_view_staff_label": "Ana Support",
            }
        )
        session.save()

    def test_leaving_ends_the_platform_session_and_forgets_it_here(self) -> None:
        with patch("apps.users.customer_view_views.api_client.end_session") as end:
            response = self.client.post(reverse("users:customer_view_leave"))
        end.assert_called_once_with(42, SESSION_ID)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response["Location"], "/login/")
        self.assertIn("cache", response["Clear-Site-Data"])
        self.assertNotIn("user_id", self.client.session)

    def test_the_banner_names_the_customer_and_the_staff_member(self) -> None:
        from django.template import Context, Template  # noqa: PLC0415

        request = RequestFactory().get("/dashboard/")
        request.session = self.client.session
        html = Template("{% include 'components/customer_view_banner.html' %}").render(Context({"request": request}))
        self.assertIn("Acme", html)
        self.assertIn("Ana Support", html)
        self.assertIn(reverse("users:customer_view_leave"), html)


class HostileCatalogTests(TestCase):
    """Django marks a translated template literal safe, so a hostile catalog entry is markup unless escaped."""

    def test_the_banner_escapes_translated_text_and_values(self) -> None:
        from django.template import Context, Template  # noqa: PLC0415
        from django.utils import translation  # noqa: PLC0415
        from django.utils.translation import trans_real  # noqa: PLC0415

        hostile = "<img src=x onerror=alert(1)>"
        request = RequestFactory().get("/dashboard/")
        request.session = {"customer_view_customer_name": hostile, "customer_view_staff_label": "Ana"}
        with translation.override("en"):
            active = trans_real._active.value
            original = active.gettext
            active.gettext = lambda message: hostile if message == "Customer view" else original(message)
            try:
                html = Template("{% include 'components/customer_view_banner.html' %}").render(
                    Context({"request": request})
                )
            finally:
                active.gettext = original
        self.assertNotIn(hostile, html)
        self.assertEqual(html.count("&lt;img src=x onerror=alert(1)&gt;"), 2)  # the label and the name, once each


def _sample(converter: object) -> str:
    name = type(converter).__name__
    return {"IntConverter": "1", "UUIDConverter": str(uuid.uuid4()), "SlugConverter": "x"}.get(name, "x")


def _portal_routes() -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []

    def walk(patterns: list[object], namespace: str) -> None:
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                if pattern.namespace == "djdt":
                    continue  # the debug toolbar exists only in development
                inner = pattern.namespace or ""
                walk(pattern.url_patterns, f"{namespace}:{inner}" if namespace and inner else inner or namespace)
            elif isinstance(pattern, URLPattern) and pattern.name:
                name = f"{namespace}:{pattern.name}" if namespace else pattern.name
                kwargs = {key: _sample(value) for key, value in getattr(pattern.pattern, "converters", {}).items()}
                try:
                    routes.append((name, reverse(name, kwargs=kwargs)))
                except Exception:  # noqa: S112  # a route reverse cannot build from samples
                    continue

    walk(get_resolver().url_patterns, "")
    assert len(routes) > 60, "the walk found too few portal routes to prove anything"
    return routes
