"""A customer view that ends while its tab is open sends that tab back to the customer's Platform page.

The staff member opened the view from Platform in a tab of its own. Leaving it, logging out of it, or
having it end (Platform refusing it, its deadline, the feature switched off) used to land on the portal's
login page, which staff never use. The answer is a page that navigates by script, not a redirect: the
portal's CSP `form-action 'self'` applies to the redirect after a form POST, and Chromium blocks a 303 to
Platform. An ordinary customer's session still ends on the login page.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.conf import settings as django_settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.common import request_context
from apps.users import session_deadlines
from apps.users.middleware import PortalAuthenticationMiddleware

PLATFORM = "https://platform.example.test"
RETURN = f"{PLATFORM}/customers/7/"
SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
SETTINGS = {
    "PLATFORM_PUBLIC_ORIGIN": PLATFORM,
    "CUSTOMER_VIEW_ENABLED": True,
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cv-return"}},
}


def refuse_processing(request: HttpRequest) -> dict[str, object]:
    raise AssertionError("a context processor ran for the customer-view ended page")


def _view_session(**changes: object) -> dict[str, object]:
    now = timezone.now()
    values: dict[str, object] = {
        "user_id": 42,
        "customer_id": 7,
        "active_customer_id": 7,
        "email": "owner@example.test",
        "portal_session_id": SESSION_ID,
        "customer_view": True,
        "customer_view_customer_id": 7,
        "customer_view_customer_name": "Acme",
        "customer_view_staff_label": "Ana Support",
        "authenticated_at": now.isoformat(),
        "session_created_at": now.isoformat(),
        "validated_at": now.isoformat(),
        "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
    }
    values.update(changes)
    return {key: value for key, value in values.items() if value is not None}


def _customer_session() -> dict[str, object]:
    return _view_session(
        customer_view=None,
        customer_view_customer_id=None,
        customer_view_customer_name=None,
        customer_view_staff_label=None,
        session_auth_hash="stored",
    )


class EndedPageAssertions(TestCase):
    def assert_ended_page(self, response: HttpResponse, url: str = RETURN) -> None:
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn("Location", response)
        html = response.content.decode()
        self.assertIn(f'href="{url}"', html)
        self.assertIn(f'data-platform-url="{url}"', html)
        self.assertIn("js/customer-view-ended.js", html)
        # Every way out tells the browser to drop the customer's pages, not only Leave.
        self.assertIn("cache", response["Clear-Site-Data"])
        # A standalone page: after the flush there is no session or user to draw the portal's chrome with,
        # and the customer's cookie-consent banner must not appear in a staff tab.
        self.assertNotIn("cookie-consent", html)
        self.assertNotIn("data-customer-view-banner", html)


@override_settings(**SETTINGS)
class LeavingTests(EndedPageAssertions):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def _start(self, **changes: object) -> None:
        # A fresh browser each time: after leaving, the client holds the deleted session cookie.
        self.client = self.client_class()
        session = self.client.session
        session.update(_view_session(**changes))
        session.save()

    def test_leaving_returns_the_tab_to_the_customer_s_platform_page(self) -> None:
        self._start()
        with patch("apps.users.customer_view_views.api_client.end_session") as end:
            response = self.client.post(reverse("users:customer_view_leave"))
        end.assert_called_once_with(42, SESSION_ID)
        self.assert_ended_page(response)
        self.assertIn("cache", response["Clear-Site-Data"])
        self.assertNotIn("user_id", self.client.session)
        self.assertNotIn("customer_view", self.client.session)

    def test_an_origin_with_a_trailing_slash_makes_no_double_slash(self) -> None:
        self._start()
        with (
            override_settings(PLATFORM_PUBLIC_ORIGIN=PLATFORM + "/"),
            patch("apps.users.customer_view_views.api_client.end_session"),
        ):
            response = self.client.post(reverse("users:customer_view_leave"))
        self.assert_ended_page(response)

    def test_a_customer_id_that_is_not_a_positive_number_returns_to_platform_s_home(self) -> None:
        for bad in ("7/../../admin", "7x", -1, 0, True, 2.5):
            with self.subTest(customer_view_customer_id=bad):
                self._start(customer_view_customer_id=bad)
                with patch("apps.users.customer_view_views.api_client.end_session"):
                    response = self.client.post(reverse("users:customer_view_leave"))
                self.assert_ended_page(response, f"{PLATFORM}/")

    def test_the_ended_page_runs_no_context_processor(self) -> None:
        # The session is gone; a processor reaching the cache or Platform could delay or break the way back.
        self._start()
        # A fresh engine (TEMPLATES changes reset it) with a processor that fails if any request render runs:
        # patching the module-level processors would miss an engine that already cached them.
        templates = copy.deepcopy(django_settings.TEMPLATES)
        templates[0]["OPTIONS"]["context_processors"].append(f"{__name__}.refuse_processing")
        with (
            override_settings(TEMPLATES=templates),
            patch("apps.users.customer_view_views.api_client.end_session"),
        ):
            response = self.client.post(reverse("users:customer_view_leave"))
        self.assert_ended_page(response)

    def test_a_missing_customer_id_is_logged_when_it_falls_back(self) -> None:
        self._start(customer_view_customer_id=None)
        with (
            patch("apps.users.customer_view_views.api_client.end_session"),
            self.assertLogs("apps.users.customer_view_views", level="WARNING") as logs,
        ):
            response = self.client.post(reverse("users:customer_view_leave"))
        self.assert_ended_page(response, f"{PLATFORM}/")
        self.assertIn("customer id", "\n".join(logs.output))

    def test_logging_out_of_a_customer_view_returns_to_platform_too(self) -> None:
        self._start()
        with patch("apps.users.views.api_client.end_session") as end:
            response = self.client.post("/logout/")
        end.assert_called_once_with(42, SESSION_ID)
        self.assert_ended_page(response)
        self.assertNotIn("user_id", self.client.session)
        self.assertNotIn("_messages", self.client.session)  # no "logged out" note waiting on the portal

    def test_opening_logout_by_its_address_keeps_the_view(self) -> None:
        self._start()
        response = self.client.get("/logout/")
        # /login/ is not a page a customer view may read; the view goes on until it is left.
        self.assertEqual((response.status_code, response["Location"]), (302, "/dashboard/"))
        self.assertTrue(self.client.session.get("customer_view"))

    def test_a_customer_s_logout_still_ends_on_the_login_page(self) -> None:
        session = self.client.session
        session.update(_customer_session())
        session.save()
        with patch("apps.users.views.api_client.end_session"):
            posted = self.client.post("/logout/")
        self.assertEqual((posted.status_code, posted["Location"]), (302, "/login/"))
        self.assertEqual(self.client.get("/logout/")["Location"], "/login/")


@override_settings(**SETTINGS)
class EndedViewTests(EndedPageAssertions):
    """Every route by which the middleware ends a session, for a customer view and for a customer."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()

    def request(self, values: dict[str, object], *, kind: str = "page") -> HttpRequest:
        headers = {"page": {}, "htmx": {"HTTP_HX_REQUEST": "true"}, "json": {"HTTP_ACCEPT": "application/json"}}[kind]
        request = self.factory.get("/dashboard/", **headers)
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        request.session.update(values)
        request.session.save()
        return request

    def _expired(self, values: dict[str, object]) -> dict[str, object]:
        request = self.request(values)
        past = timezone.now() - timedelta(minutes=1)
        session_deadlines.store(request.session, session_deadlines.SessionDeadlines("customer_view", past, past))
        return dict(request.session.items())

    def routes(self, values: dict[str, object]) -> dict[str, tuple[dict[str, object], dict[str, object]]]:
        """route -> (session values without unset keys, settings for it)."""
        routes = {
            "feature switched off": (values, {"CUSTOMER_VIEW_ENABLED": False}),
            "no Platform session": ({**values, "portal_session_id": None}, {"PORTAL_SESSION_ID_REQUIRED": True}),
            "no deadlines": (values, {"PORTAL_SESSION_DEADLINES_REQUIRED": True}),
            "deadline passed": (self._expired(values), {"PORTAL_SESSION_DEADLINES_REQUIRED": True}),
            "Platform refused it": (values, {}),
        }
        return {
            route: ({k: v for k, v in kept.items() if v is not None}, changed)
            for route, (kept, changed) in routes.items()
        }

    def through(self, request: HttpRequest, route: str) -> tuple[HttpResponse, MagicMock]:
        def page(request: HttpRequest) -> HttpResponse:
            if route == "Platform refused it":
                request_context.mark_rejected()
            return HttpResponse("page")

        view = MagicMock(side_effect=page)
        return PortalAuthenticationMiddleware(view)(request), view

    def test_an_ended_customer_view_sends_its_tab_back_to_platform(self) -> None:
        for route, (values, settings) in self.routes(_view_session()).items():
            for kind in ("page", "htmx", "json"):
                with self.subTest(route=route, kind=kind), override_settings(**settings):
                    request = self.request(values, kind=kind)
                    with patch("apps.users.middleware.api_client.validate_session_secure", return_value=True):
                        response, _view = self.through(request, route)
                    if kind == "page":
                        self.assert_ended_page(response)
                    elif kind == "htmx":
                        self.assertEqual((response.status_code, response["HX-Redirect"]), (200, RETURN))
                    else:
                        self.assertEqual(response.status_code, 401)
                        self.assertEqual(json.loads(response.content)["redirect"], RETURN)
                    self.assertIn("cache", response.get("Clear-Site-Data", ""))
                    self.assertNotIn("customer_view", request.session)

    def test_an_ended_customer_session_still_goes_to_the_login_page(self) -> None:
        for route, (values, settings) in self.routes(_customer_session()).items():
            if route == "feature switched off":
                continue  # the switch ends customer views only
            for kind in ("page", "htmx", "json"):
                with self.subTest(route=route, kind=kind), override_settings(**settings):
                    request = self.request(values, kind=kind)
                    with patch("apps.users.middleware.api_client.validate_session_secure", return_value=True):
                        response, _view = self.through(request, route)
                    if kind == "page":
                        self.assertEqual(response.status_code, 302)
                        self.assertTrue(response["Location"].startswith("/login/"))
                    elif kind == "htmx":
                        self.assertEqual(response["HX-Redirect"], "/login/")
                    else:
                        self.assertEqual(json.loads(response.content)["redirect"], "/login/")
                    self.assertNotIn("user_id", request.session)
