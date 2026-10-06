"""Session termination failures must stay recoverable through the complete middleware stack."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Literal
from unittest.mock import patch

from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.db import OperationalError, connection, transaction
from django.http import HttpRequest, HttpResponse
from django.test import Client, TestCase, override_settings
from django.urls import include, path
from django.utils import timezone
from requests import Response

from apps.api_client.services import PlatformAPIClient
from apps.common.store_unavailable import STORE_UNAVAILABLE_RETRY_AFTER_SECONDS, store_unavailable_message
from apps.users.views import PASSWORD_RESET_SESSION_KEY

Site = Literal["age", "validation", "integrity", "timeout", "logout", "reset"]
SITES: tuple[Site, ...] = ("age", "validation", "integrity", "timeout", "logout", "reset")
MARKER = "Authenticated view reached"


def protected_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(MARKER)


urlpatterns = [
    path("wp7/protected/", protected_view),
    path("", include("config.urls")),
]

# Retain every production middleware; the development toolbar is not part of that stack.
PRODUCTION_MIDDLEWARE = tuple(
    middleware for middleware in settings.MIDDLEWARE if not middleware.startswith("debug_toolbar.")
)


@override_settings(
    ROOT_URLCONF=__name__,
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_ALLOW_INSECURE_HTTP=True,
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class SessionTerminationUnavailableTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.rejected = False
        # Bypass the suite's singleton API mocks, keeping the signed transport real.
        platform = PlatformAPIClient()
        self.enterContext(patch("apps.users.middleware.api_client", platform))
        self.enterContext(patch("apps.users.views.api_client", platform))
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))
        self.deletes: list[str] = []

    def platform(self, **kwargs: object) -> Response:
        url = str(kwargs["url"])
        if url.endswith("/users/session/validate/"):
            payload: dict[str, object] = {"active": not self.rejected, "membership_hash": "before"}
        elif url.endswith("/users/password/reset/confirm/"):
            payload = {"success": True}
        elif url.endswith("/localisation/"):
            payload = {
                "success": True,
                "localisation": {
                    "default_language": "en",
                    "default_country": "RO",
                    "timezone": "Europe/Bucharest",
                    "customer_date_format": "%d.%m.%Y",
                },
            }
        else:
            raise AssertionError(f"Unexpected Platform request: {url}")
        response = Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(payload).encode()
        return response

    def seed(self, site: Site) -> tuple[Client, str]:
        client = Client(raise_request_exception=False)
        session = client.session
        now = timezone.now()
        session.update(
            {
                "user_id": 7,
                "customer_id": 42,
                "active_customer_id": 42,
                "email": "session@example.com",
                "session_auth_hash": "current",
                "authenticated_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(hours=1)).isoformat(),
                "last_activity": time.time(),
                "security_fingerprint": {
                    "ip_hash": hashlib.sha256(b"127.0.0.1").hexdigest()[:16],
                    "user_agent_hash": hashlib.sha256(b"").hexdigest()[:16],
                    "created_at": time.time(),
                },
            }
        )
        if site == "age":
            session["authenticated_at"] = (now - timedelta(days=31)).isoformat()
        elif site == "validation":
            session["next_validate_at"] = (now - timedelta(minutes=10)).isoformat()
        elif site == "integrity":
            session["security_fingerprint"]["ip_hash"] = "changed"
        elif site == "timeout":
            session["last_activity"] = time.time() - 3601
        elif site == "reset":
            session[PASSWORD_RESET_SESSION_KEY] = {"uid": "Nw", "token": "reset-token"}
        session.save()
        key = session.session_key
        assert key is not None
        return client, key

    def request_site(self, client: Client, site: Site, accept: str) -> HttpResponse:
        if site == "logout":
            return client.post("/logout/", HTTP_ACCEPT=accept)
        if site == "reset":
            return client.post(
                "/password-reset/confirm/",
                {"new_password": "Secure-new-password-42!", "confirm_password": "Secure-new-password-42!"},
                HTTP_ACCEPT=accept,
            )
        return client.get("/wp7/protected/", HTTP_ACCEPT=accept)

    def assert_failure_matrix(self, accept: str) -> None:
        for site in SITES:
            with self.subTest(site=site, accept=accept):
                client, key = self.seed(site)
                self.rejected = site == "validation"
                self.deletes.clear()

                def reject_delete(
                    execute: Callable[..., object], sql: str, params: object, many: bool, context: dict[str, object]
                ) -> object:
                    if sql.lstrip().upper().startswith("DELETE") and "django_session" in sql:
                        self.deletes.append(sql)
                        raise OperationalError("session delete unavailable")
                    return execute(sql, params, many, context)

                with transaction.atomic(), connection.execute_wrapper(reject_delete):
                    response = self.request_site(client, site, accept)
                self.assertTrue(self.deletes, "The real session DELETE must reach the database")
                self.assertEqual(response.status_code, 503, response.content[:300])
                self.assertNotIn(MARKER.encode(), response.content)
                self.assertNotIn("Location", response)
                self.assertEqual(response["Retry-After"], str(STORE_UNAVAILABLE_RETRY_AFTER_SECONDS))
                self.assertIn("no-store", response["Cache-Control"])
                cookie = response.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(cookie.value, "")
                self.assertEqual(cookie["max-age"], 0)
                self.assertEqual(cookie["path"], settings.SESSION_COOKIE_PATH)
                self.assertEqual(cookie["domain"], settings.SESSION_COOKIE_DOMAIN or "")
                self.assertEqual(cookie["samesite"], settings.SESSION_COOKIE_SAMESITE)
                self.assertIn("1970", cookie["expires"])
                self.assertTrue(response.wsgi_request.session.is_empty())
                self.assertIsNone(response.wsgi_request.session.session_key)
                # Failed deletion leaves the server row intact, but the browser drops its key.
                self.assertTrue(Session.objects.filter(session_key=key).exists())
                if accept == "application/json":
                    self.assertEqual(
                        json.loads(response.content),
                        {
                            "success": False,
                            "error": store_unavailable_message(),
                            "retry_after": STORE_UNAVAILABLE_RETRY_AFTER_SECONDS,
                        },
                    )
                else:
                    self.assertContains(response, store_unavailable_message(), status_code=503)
                    self.assertIn("text/html", response["Content-Type"])

                # Recovery uses the same real backend and preserves each site's redirect.
                recovered_client, recovered_key = self.seed(site)
                recovered = self.request_site(recovered_client, site, accept)
                self.assertEqual(recovered.status_code, 302)
                self.assertIn("/login/", recovered["Location"])
                self.assertFalse(Session.objects.filter(session_key=recovered_key).exists())
                self.assertTrue(recovered.wsgi_request.session.is_empty())

    def test_browser_session_deletion_failure_at_every_site(self) -> None:
        self.assert_failure_matrix("text/html")

    def test_json_session_deletion_failure_at_every_site(self) -> None:
        self.assert_failure_matrix("application/json")
