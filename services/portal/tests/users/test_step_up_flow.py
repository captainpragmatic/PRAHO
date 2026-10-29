"""Platform asks for the password again before a sensitive action: the portal asks, then goes back.

A 403 ``reauth_required`` from Platform is never an ended session. The API client raises
``StepUpRequiredError`` and records it, and once the view returns, the auth middleware sends the browser
to ``/confirm-identity/`` with the page it came from. A session refusal in the same request still
wins: the session ends. Messages the view queued for the refused attempt are dropped; messages that
were waiting before it stay for the next page.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import timedelta
from unittest.mock import MagicMock
from urllib.parse import quote

from django.contrib import messages
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.template import engines
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIClient, PlatformAPIError, StepUpRequiredError
from apps.common import request_context
from apps.users.middleware import PortalAuthenticationMiddleware

SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
SESSION_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "step-up"}},
}


def _platform_answer(status: int, body: dict[str, object]) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.headers = {"content-type": "application/json"}
    response.json.return_value = body
    return response


def _step_up() -> MagicMock:
    return _platform_answer(403, {"success": False, "code": "reauth_required"})


def _refusal() -> MagicMock:
    return _platform_answer(401, {"active": False, "error": "Session validation failed"})


def _asks_for_confirmation(request: HttpRequest) -> HttpResponse:
    with contextlib.suppress(PlatformAPIError):  # the view shows its own "could not" state
        PlatformAPIClient()._handle_api_response(_step_up(), "/billing/gift-cards/reveal/")
    return HttpResponse("page")


class ClientTests(SimpleTestCase):
    def test_a_reauth_answer_raises_step_up_and_never_ends_the_session(self) -> None:
        for handle in ("_handle_api_response", "_handle_binary_response"):
            with self.subTest(path=handle), request_context.bound(SESSION_ID, 42):
                with self.assertRaises(StepUpRequiredError):
                    getattr(PlatformAPIClient(), handle)(_step_up(), "/billing/gift-cards/reveal/")
                self.assertTrue(request_context.step_up_required())
                self.assertFalse(request_context.rejected())

    def test_control_a_session_refusal_is_still_a_refusal(self) -> None:
        refusals = {
            "401 active false": _refusal(),
            "a code beside active": _platform_answer(403, {"active": False, "code": "reauth_required"}),
        }
        for name, answer in refusals.items():
            with self.subTest(case=name), request_context.bound(SESSION_ID, 42):
                with self.assertRaises(PlatformAPIError) as raised:
                    PlatformAPIClient()._handle_api_response(answer, "/customers/")
                self.assertNotIsInstance(raised.exception, StepUpRequiredError)
                self.assertTrue(request_context.rejected())
                self.assertFalse(request_context.step_up_required())

    def test_the_flag_does_not_outlive_its_request(self) -> None:
        with request_context.bound(SESSION_ID, 42):
            request_context.mark_step_up_required()
        with request_context.bound(SESSION_ID, 42):
            self.assertFalse(request_context.step_up_required())


@override_settings(**SESSION_SETTINGS)
class MiddlewareTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()

    def request(
        self,
        path: str = "/billing/gift-cards/abc/?tab=code",
        *,
        method: str = "get",
        cookies: dict[str, str] | None = None,
        **extra: str,
    ) -> HttpRequest:
        request = getattr(self.factory, method)(path, **extra)
        request.COOKIES.update(cookies or {})
        SessionMiddleware(lambda request: HttpResponse()).process_request(request)
        now = timezone.now()
        request.session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": "user@example.com",
                "session_auth_hash": "stored",
                "portal_session_id": SESSION_ID,
                "authenticated_at": now.isoformat(),
                "session_created_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        request.session.save()
        MessageMiddleware(lambda request: HttpResponse()).process_request(request)
        return request

    def run_through(self, request: HttpRequest, view: Callable[[HttpRequest], HttpResponse]) -> HttpResponse:
        return PortalAuthenticationMiddleware(view)(request)

    def test_a_page_that_needs_confirmation_goes_to_confirm_and_names_itself(self) -> None:
        view = MagicMock(side_effect=_asks_for_confirmation)
        request = self.request()
        response = self.run_through(request, view)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["Location"], "/confirm-identity/?next=" + quote("/billing/gift-cards/abc/?tab=code", safe="")
        )
        view.assert_called_once()
        self.assertEqual(request.session["user_id"], 42)  # the session lives on
        self.assertFalse(request_context.step_up_required())

    def test_a_form_post_goes_back_to_the_page_that_sent_it(self) -> None:
        cases = {
            "same site": ("http://testserver/billing/gift-cards/abc/", "/billing/gift-cards/abc/"),
            "another site": ("https://evil.example/billing/", "/dashboard/"),
            "no referer": ("", "/dashboard/"),
        }
        for name, (referer, back) in cases.items():
            with self.subTest(case=name):
                extra = {"HTTP_REFERER": referer} if referer else {}
                request = self.request("/billing/gift-cards/abc/reveal/", method="post", **extra)
                response = self.run_through(request, _asks_for_confirmation)
                self.assertEqual(response["Location"], "/confirm-identity/?next=" + quote(back, safe=""))

    def test_an_htmx_request_is_sent_by_header_not_by_a_swapped_redirect(self) -> None:
        request = self.request(
            "/billing/gift-cards/abc/reveal/",
            method="post",
            HTTP_HX_REQUEST="true",
            HTTP_HX_CURRENT_URL="http://testserver/billing/gift-cards/abc/",
        )
        response = self.run_through(request, _asks_for_confirmation)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["HX-Redirect"], "/confirm-identity/?next=" + quote("/billing/gift-cards/abc/", safe="")
        )

    def test_a_download_goes_back_to_the_page_with_the_link(self) -> None:
        def download(request: HttpRequest) -> HttpResponse:
            with contextlib.suppress(PlatformAPIError):
                PlatformAPIClient()._handle_binary_response(_step_up(), "/gdpr/export/download/")
            return HttpResponse(status=404)

        request = self.request("/privacy/export/download/9/", HTTP_REFERER="http://testserver/privacy/export/")
        response = self.run_through(request, download)
        self.assertEqual(response["Location"], "/confirm-identity/?next=" + quote("/privacy/export/", safe=""))

    def test_a_session_refusal_wins_over_a_confirmation_request(self) -> None:
        def both(request: HttpRequest) -> HttpResponse:
            _asks_for_confirmation(request)
            with contextlib.suppress(PlatformAPIError):
                PlatformAPIClient()._handle_api_response(_refusal(), "/customers/")
            return HttpResponse("page")

        request = self.request()
        response = self.run_through(request, both)
        self.assertTrue(response["Location"].startswith("/login/"))
        self.assertNotIn("user_id", request.session)

    def test_messages_queued_for_the_refused_attempt_are_dropped_and_older_ones_kept(self) -> None:
        for rendering in (False, True):
            with self.subTest(view_renders=rendering):
                earlier = self.request()
                messages.info(earlier, "Saved earlier")  # waiting from the previous page
                jar = self._store(earlier, HttpResponse(), {})
                request = self.request(cookies=jar)

                def view(request: HttpRequest, rendering: bool = rendering) -> HttpResponse:
                    _asks_for_confirmation(request)
                    messages.error(request, "Could not reveal the code")
                    if rendering:  # rendering a page reads, and so spends, every message
                        page = engines["django"].from_string("{% for m in messages %}{{ m }}{% endfor %}")
                        return HttpResponse(page.render({"messages": messages.get_messages(request)}))
                    return HttpResponse("redirect elsewhere", status=302)

                response = self.run_through(request, view)
                shown = self.request("/confirm-identity/", cookies=self._store(request, response, jar))
                self.assertEqual([str(m) for m in messages.get_messages(shown)], ["Saved earlier"])

    @staticmethod
    def _store(request: HttpRequest, response: HttpResponse, jar: dict[str, str]) -> dict[str, str]:
        """The browser's cookies after this response: it keeps what is not set again, drops what is deleted."""
        response = MessageMiddleware(lambda request: HttpResponse()).process_response(request, response)
        cookies = dict(jar)
        for name, morsel in response.cookies.items():
            if str(morsel["max-age"]) == "0":
                cookies.pop(name, None)
            else:
                cookies[name] = morsel.value
        return cookies
