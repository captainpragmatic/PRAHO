"""A session save that gives up under contention is answered as a temporary outage (ADR-0055).

Whether it gives up while the response is saved, or inside a view (a password change rotating the
key, a purchase saving mid-request), the portal answers its usual 503 with Retry-After instead of a
server error, keeping what the response already carried.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import path

from apps.common.session_store import SessionMiddleware, SessionSaveContended, SessionStore


def contended_view(request: HttpRequest) -> HttpResponse:
    raise SessionSaveContended("gave up")


urlpatterns = [path("contended/", contended_view)]

PRODUCTION_MIDDLEWARE = tuple(m for m in settings.MIDDLEWARE if not m.startswith("debug_toolbar."))


@override_settings(ROOT_URLCONF=__name__, MIDDLEWARE=PRODUCTION_MIDDLEWARE, DEBUG=False)
class ContendedSessionResponseTests(TestCase):
    def test_contention_inside_a_view_is_a_503_through_the_whole_stack(self) -> None:
        self.assertIn("apps.common.session_store.SessionMiddleware", settings.MIDDLEWARE)
        client = self.client_class(raise_request_exception=False)
        # The probe URL is treated as public, so the request reaches the view through the stack.
        public = patch("apps.users.middleware.PortalAuthenticationMiddleware.is_public_url", return_value=True)
        for accept in ("text/html", "application/json"):
            with self.subTest(accept=accept), public:
                response = client.get("/contended/", HTTP_ACCEPT=accept)
                self.assertEqual(response.status_code, 503)
                self.assertIn("Retry-After", response)

    def test_a_contended_response_save_keeps_cookies_and_security_headers(self) -> None:
        store = SessionStore()
        store["user_id"] = 7
        store.save()
        request = RequestFactory().get("/page/", HTTP_ACCEPT="text/html")
        request.COOKIES[settings.SESSION_COOKIE_NAME] = store.session_key or ""
        middleware = SessionMiddleware(lambda request: HttpResponse("page"))
        middleware.process_request(request)
        request.session["cart"] = {"items": [1]}
        page = HttpResponse("page")
        page.set_cookie("messages", "", max_age=0)  # a notice the page already consumed
        page["Content-Security-Policy"] = "default-src 'self'"
        with (
            patch("django.db.models.query.QuerySet.update", return_value=0),
            patch("apps.common.session_store._back_off"),
        ):
            response = middleware.process_response(request, page)
        self.assertEqual(response.status_code, 503)
        self.assertIn("messages", response.cookies)
        self.assertEqual(response["Content-Security-Policy"], "default-src 'self'")
        self.assertIn("no-cache", response["Cache-Control"])

    def test_a_value_that_is_not_json_is_rejected_not_silently_dropped(self) -> None:
        store = SessionStore()
        store["account_id"] = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
        store.save()
        loaded = SessionStore(session_key=store.session_key)
        loaded["account_id"] = uuid.UUID("1b4e28ba-2fa1-11d2-883f-0016d3cca427")  # equal as text only
        with self.assertRaises(TypeError):
            loaded.save()
