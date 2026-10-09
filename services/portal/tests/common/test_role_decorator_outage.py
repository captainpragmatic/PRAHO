"""Role verification outages must stop protected views without reporting missing roles."""

from __future__ import annotations

import json
import time
from typing import Literal
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import Client, SimpleTestCase, override_settings
from django.urls import include, path
from django.utils.html import escape

from apps.common.decorators import _fetch_user_memberships, require_customer_role, require_support_access

Failure = Literal["connection", "maintenance", "rate_limit"]
RequestKind = Literal["page", "json", "htmx"]
CacheState = Literal["cold", "expired", "revoked", "realtime"]
VIEW_MARKER = "Protected role view ran"
VIEW_CALLS: list[str] = []
FAILURES: tuple[Failure, ...] = ("connection", "maintenance", "rate_limit")
REQUEST_KINDS: tuple[RequestKind, ...] = ("page", "json", "htmx")


def _sentinel(request: HttpRequest) -> HttpResponse:
    VIEW_CALLS.append(request.path)
    return HttpResponse(VIEW_MARKER)


urlpatterns = [
    path("role-check/reply/", require_support_access()(_sentinel)),
    path("role-check/", require_customer_role(["owner"])(_sentinel)),
    path("role-check/realtime/", require_customer_role(["owner"], realtime_verification=True)(_sentinel)),
    path("", include("config.urls")),
]


def _api_response(status: int, payload: dict[str, object], *, retry_after: int | None = None) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    response._content = json.dumps(payload).encode()
    return response


@override_settings(
    ROOT_URLCONF=__name__,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "role-decorator-outage",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_BASE_URL="https://platform.example.test/api",
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class RoleDecoratorOutageTests(SimpleTestCase):
    def _client(self, *, expired: bool = False, cold: bool = False, role: str = "owner") -> Client:
        cache.clear()
        VIEW_CALLS.clear()
        client = Client(raise_request_exception=False)
        session = client.session
        session["user_id"] = 456
        session["customer_id"] = 123
        session["selected_customer_id"] = 123
        if not cold:
            session["user_memberships"] = [{"customer_id": 123, "role": role}]
            session["user_memberships_fetched_at"] = 1.0 if expired else time.time()
        session.save()
        return client

    def _get(self, client: Client, kind: RequestKind, *, realtime: bool = False) -> HttpResponse:
        headers = {"Accept": "application/json"} if kind == "json" else {"HX-Request": "true"} if kind == "htmx" else {}
        return client.get("/role-check/realtime/" if realtime else "/role-check/", headers=headers)

    def _assert_degraded(self, response: HttpResponse, failure: Failure, kind: RequestKind) -> None:
        # HTMX does not swap 4xx/5xx responses, so an HTMX outage notice is sent with 200.
        status = 200 if kind == "htmx" else 429 if failure == "rate_limit" else 503
        self.assertEqual(VIEW_CALLS, [])
        self.assertNotContains(response, VIEW_MARKER, status_code=response.status_code)
        self.assertEqual(response.status_code, status)
        self.assertNotContains(response, "Role not found", status_code=status)
        self.assertNotIn("Location", response)
        if failure == "connection":
            message = "This information is temporarily unavailable. Please try again shortly."
            heading = "Temporarily unavailable"
            self.assertNotIn("Retry-After", response)
        elif failure == "maintenance":
            message = "We're carrying out scheduled maintenance. Your data is safe - please try again in 60 seconds."
            heading = "Scheduled maintenance"
            self.assertEqual(response["Retry-After"], "60")
        else:
            message = "We're receiving many requests right now. Please try again in 60 seconds."
            heading = "Temporarily rate limited"
            self.assertEqual(response["Retry-After"], "60")

        if kind == "json":
            self.assertEqual(response["Content-Type"], "application/json")
            self.assertEqual(
                json.loads(response.content),
                {"error": message, "retry_after": None if failure == "connection" else 60},
            )
            self.assertTemplateNotUsed(response, "base.html")
        else:
            template = (
                "components/rate_limit_inline_alert.html"
                if failure == "rate_limit"
                else "components/maintenance_inline_alert.html"
            )
            self.assertTemplateUsed(response, template)
            if kind == "page":
                self.assertTemplateUsed(
                    response,
                    "common/rate_limited.html" if failure == "rate_limit" else "common/platform_unavailable.html",
                )
                self.assertTemplateUsed(response, "base.html")
            else:
                self.assertTemplateNotUsed(response, "base.html")
            self.assertContains(response, heading, status_code=status)
            self.assertContains(response, escape(message), status_code=status)

    def _assert_outage_matrix(self, state: CacheState) -> None:
        for failure in FAILURES:
            for kind in REQUEST_KINDS:
                with self.subTest(state=state, failure=failure, kind=kind):
                    client = self._client(expired=state in {"expired", "revoked"}, cold=state == "cold")
                    if state == "revoked":
                        # A successful empty refresh precedes the outage on the next request.
                        request = HttpRequest()
                        request.session = client.session
                        with patch(
                            "apps.common.outbound_http._send",
                            return_value=_api_response(200, {"success": True, "results": []}),
                        ):
                            self.assertEqual(_fetch_user_memberships(request), [])
                        request.session.save()

                    unavailable = _api_response(
                        429 if failure == "rate_limit" else 503,
                        {"error": "rate_limited" if failure == "rate_limit" else "maintenance"},
                        retry_after=60,
                    )
                    with patch(
                        "apps.common.outbound_http._send",
                        side_effect=requests.exceptions.ConnectionError("offline") if failure == "connection" else None,
                        return_value=unavailable,
                    ):
                        response = self._get(client, kind, realtime=state == "realtime")
                    self._assert_degraded(response, failure, kind)

                    # A later authoritative owner response can still grant access.
                    allowed = (
                        {"success": True, "has_access": True, "role": "owner"}
                        if state == "realtime"
                        else {"success": True, "results": [{"id": 123, "role": "owner"}]}
                    )
                    with patch("apps.common.outbound_http._send", return_value=_api_response(200, allowed)):
                        recovered = self._get(client, kind, realtime=state == "realtime")
                    self.assertContains(recovered, VIEW_MARKER)
                    self.assertEqual(VIEW_CALLS, ["/role-check/realtime/" if state == "realtime" else "/role-check/"])

    def test_expired_cache_reply_post_keeps_form_and_blocks_support_view(self) -> None:
        for failure in FAILURES:
            with self.subTest(failure=failure):
                client = self._client(expired=True)
                unavailable = _api_response(
                    429 if failure == "rate_limit" else 503,
                    {"error": "rate_limited" if failure == "rate_limit" else "maintenance"},
                    retry_after=60,
                )
                with patch(
                    "apps.common.outbound_http._send",
                    side_effect=requests.exceptions.ConnectionError("offline") if failure == "connection" else None,
                    return_value=unavailable,
                ):
                    response = client.post(
                        "/role-check/reply/",
                        {"message": "An unsent draft"},
                        headers={"HX-Request": "true", "HX-Target": "ticket-status-and-comments"},
                    )

                self.assertEqual(response.get("HX-Retarget"), "#toast-container")
                self.assertEqual(response.get("HX-Reswap"), "beforeend")
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "components/toast.html")
                self.assertContains(response, 'role="alert"')
                self.assertContains(
                    response,
                    "temporarily unavailable"
                    if failure == "connection"
                    else "scheduled maintenance"
                    if failure == "maintenance"
                    else "many requests",
                )
                self.assertNotContains(response, VIEW_MARKER)
                self.assertEqual(VIEW_CALLS, [])
                self.assertEqual(client.session["user_memberships_fetched_at"], 1.0)

    def test_cold_cache_outage_matrix(self) -> None:
        self._assert_outage_matrix("cold")

    def test_expired_cache_outage_matrix(self) -> None:
        self._assert_outage_matrix("expired")

    def test_revoked_owner_then_outage_matrix(self) -> None:
        self._assert_outage_matrix("revoked")

    def test_realtime_verification_outage_matrix(self) -> None:
        self._assert_outage_matrix("realtime")

    def test_empty_success_clears_owner_and_refresh_timestamp_before_denial(self) -> None:
        client = self._client(expired=True)
        before = time.time()
        with patch(
            "apps.common.outbound_http._send",
            return_value=_api_response(200, {"success": True, "results": []}),
        ):
            response = self._get(client, "page")
        self.assertEqual(client.session["user_memberships"], [])
        self.assertGreaterEqual(client.session["user_memberships_fetched_at"], before)
        self.assertLessEqual(client.session["user_memberships_fetched_at"], time.time())
        self.assertEqual(response.status_code, 403)
        self.assertTemplateUsed(response, "403.html")
        self.assertEqual(VIEW_CALLS, [])
        self.assertNotContains(response, "Role not found", status_code=403)

    def test_authoritative_denials_render_403_page(self) -> None:
        messages = {
            "no_customer": "No customer selected",
            "missing_role": "Role not found",
            "wrong_role": "Insufficient permissions",
            "realtime_denied": "Access denied",
            "fetch_error": "Role not found",
            "realtime_error": "Access denied",
        }
        for denial, message in messages.items():
            for kind in REQUEST_KINDS:
                with self.subTest(denial=denial, kind=kind):
                    client = self._client(cold=denial == "missing_role", expired=denial == "fetch_error", role="viewer")
                    if denial == "no_customer":
                        with patch("apps.common.decorators._get_selected_customer_id", return_value=None):
                            response = self._get(client, kind)
                    else:
                        authoritative = _api_response(
                            403 if denial in {"fetch_error", "realtime_error"} else 200,
                            {"error": "denied"}
                            if denial in {"fetch_error", "realtime_error"}
                            else {"success": True, "results": [], "has_access": False},
                        )
                        with patch("apps.common.outbound_http._send", return_value=authoritative):
                            response = self._get(client, kind, realtime=denial in {"realtime_denied", "realtime_error"})
                    self.assertEqual(response.status_code, 403)
                    if kind == "page":
                        self.assertTemplateUsed(response, "403.html")
                        self.assertContains(response, "Access Denied", status_code=403)
                        self.assertNotContains(response, "Role not found", status_code=403)
                    elif kind == "json":
                        self.assertEqual(json.loads(response.content), {"error": message})
                    else:
                        self.assertTemplateUsed(response, "components/permission_denied_partial.html")
                        self.assertContains(response, message, status_code=403)
                        self.assertTemplateNotUsed(response, "base.html")
                    self.assertNotContains(response, VIEW_MARKER, status_code=403)
                    self.assertEqual(VIEW_CALLS, [])
