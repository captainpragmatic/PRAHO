"""The portal names its Platform session in every call it makes for a customer (ADR-0017 section 5)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common import request_context
from apps.users.middleware import PortalAuthenticationMiddleware

SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
SESSION_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "owned-sessions"}},
}


def _refusal() -> MagicMock:
    response = MagicMock()
    response.status_code = 401
    response.headers = {"content-type": "application/json"}
    response.json.return_value = {"active": False, "error": "Session validation failed"}
    return response


class SignedBodyTests(SimpleTestCase):
    def setUp(self) -> None:
        self.client_ = PlatformAPIClient()

    def body(self, data: dict[str, object] | None, user_id: int | None) -> dict[str, object]:
        return json.loads(self.client_._prepare_json_body(data, user_id)[0])

    def test_a_call_for_a_customer_names_the_bound_session(self) -> None:
        with request_context.bound(SESSION_ID, 42):
            self.assertEqual(self.body({}, 42)["session_id"], SESSION_ID)
            self.assertIs(self.body({"user_id": 42}, None)["interactive"], True)
            with request_context.background():
                self.assertIs(self.body({}, 42)["interactive"], False)

    def test_every_call_inside_a_signed_in_request_names_the_user_and_session(self) -> None:
        with request_context.bound(SESSION_ID, 42):
            # A call that names only a customer is bound too, so no endpoint escapes the session check.
            body = self.body({"customer_id": 7}, None)
            self.assertEqual((body["user_id"], body["session_id"]), (42, SESSION_ID))
        self.assertNotIn("session_id", self.body({}, 42))  # nothing bound outside a request
        with request_context.bound(SESSION_ID, None):  # a session without its user binds nothing
            self.assertNotIn("session_id", self.body({"customer_id": 7}, None))

    def test_an_explicit_session_is_never_overwritten(self) -> None:
        with request_context.bound(SESSION_ID, 42):
            self.assertEqual(self.body({"session_id": "other"}, 42)["session_id"], "other")

    def test_every_call_echoes_the_window_its_browser_was_given_and_nothing_else(self) -> None:
        window = "2026-10-29T18:00:00.123456+00:00"
        with request_context.bound(SESSION_ID, 42, window):
            self.assertEqual(self.body({}, 42)["step_up_at"], window)
            # A caller's own value never replaces the browser's (ADR-0017 section 7).
            self.assertEqual(self.body({"step_up_at": "forged"}, 42)["step_up_at"], window)
        with request_context.bound(SESSION_ID, 42):  # a session that was never given a window
            self.assertNotIn("step_up_at", self.body({"step_up_at": "forged"}, 42))
        self.assertNotIn("step_up_at", self.body({"step_up_at": "forged"}, 42))  # nothing bound

    def test_a_refusal_is_recorded_for_the_bound_session_only(self) -> None:
        with request_context.bound(SESSION_ID, 42):
            with self.assertRaises(PlatformAPIError):
                self.client_._handle_api_response(_refusal(), "/customers/")
            self.assertTrue(request_context.rejected())
        with request_context.bound(None):
            with self.assertRaises(PlatformAPIError):
                self.client_._handle_api_response(_refusal(), "/customers/")
            self.assertFalse(request_context.rejected())


@override_settings(**SESSION_SETTINGS)
class MiddlewareTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        # The suite's conftest turns the rule off for hand-built sessions; this is the rule's own test.
        required = override_settings(PORTAL_SESSION_ID_REQUIRED=True)
        required.enable()
        self.addCleanup(required.disable)
        self.factory = RequestFactory()

    def request(self, path: str = "/dashboard/", *, session_id: str | None = SESSION_ID) -> HttpRequest:
        request = self.factory.get(path)
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        now = timezone.now()
        request.session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": "user@example.com",
                "session_auth_hash": "stored",
                "authenticated_at": now.isoformat(),
                "session_created_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        if session_id is not None:
            request.session["portal_session_id"] = session_id
        request.session.save()
        return request

    def run_through(self, request: HttpRequest, view: Callable[[HttpRequest], HttpResponse]) -> HttpResponse:
        return PortalAuthenticationMiddleware(view)(request)

    def test_a_session_from_before_this_release_ends_once(self) -> None:
        view = MagicMock(return_value=HttpResponse("page"))
        request = self.request(session_id=None)
        response = self.run_through(request, view)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/login/"))
        view.assert_not_called()
        self.assertNotIn("user_id", request.session)

    def test_a_refusal_during_the_view_ends_the_session_even_when_the_view_caught_it(self) -> None:
        def view(request: HttpRequest) -> HttpResponse:
            with contextlib.suppress(PlatformAPIError):  # the page renders its own "could not load" state
                PlatformAPIClient()._handle_api_response(_refusal(), "/customers/")
            return HttpResponse("page")

        request = self.request()
        response = self.run_through(request, view)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("user_id", request.session)
        self.assertFalse(request_context.rejected())  # nothing leaks into the next request

    def test_a_refusal_answers_a_script_and_htmx_in_a_form_each_can_follow(self) -> None:
        refuse = lambda request: (request_context.mark_rejected(), HttpResponse())[1]  # noqa: E731
        script = self.request()
        script.META["HTTP_ACCEPT"] = "application/json"
        self.assertEqual(self.run_through(script, refuse).status_code, 401)
        htmx = self.request()
        htmx.META["HTTP_HX_REQUEST"] = "true"
        response = self.run_through(htmx, refuse)
        self.assertEqual(response.status_code, 200)  # HTMX acts on neither a 401 nor a redirect it would swap in
        self.assertEqual(response["HX-Redirect"], "/login/")

    def test_public_routes_are_bound_too(self) -> None:
        seen: dict[str, object] = {}

        def view(request: HttpRequest) -> HttpResponse:
            seen.update(request_context.signed_fields())
            return HttpResponse()

        self.run_through(self.request("/api/cookie-consent/"), view)
        self.assertEqual(seen.get("session_id"), SESSION_ID)
        self.assertEqual(request_context.signed_fields(), {})


@override_settings(**SESSION_SETTINGS)
class LogoutTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com", "portal_session_id": SESSION_ID})
        session.save()

    def test_logout_ends_the_platform_session(self) -> None:
        with patch("apps.users.views.api_client.end_session") as end:
            response = self.client.post("/logout/")
        end.assert_called_once_with(42, SESSION_ID)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("user_id", self.client.session)

    def test_logout_still_ends_the_browser_session_when_platform_already_ended_it(self) -> None:
        def already_ended(user_id: int, session_id: str) -> None:
            PlatformAPIClient()._handle_api_response(_refusal(), "/users/session/end/")

        with patch("apps.users.views.api_client.end_session", side_effect=already_ended):
            response = self.client.post("/logout/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/login/")  # logout's own redirect, not a second one
        self.assertNotIn("user_id", self.client.session)
