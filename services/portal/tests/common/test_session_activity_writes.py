"""An authenticated request that changes nothing does not rewrite the session.

Every authenticated request used to stamp `last_activity`, so every one rewrote the whole
session row. Two concurrent requests of one customer then raced, and the later save could undo
the earlier one's changes (a cart edit, a company switch). The stamp is now refreshed at most
once a minute, and a session without one gets one at once (idle timeout depends on it).
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import include, path
from django.utils import timezone
from requests import Response

from apps.api_client.services import PlatformAPIClient
from apps.common.middleware import SessionSecurityMiddleware

MARKER = "Authenticated view reached"


def protected_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(MARKER)


urlpatterns = [
    path("activity/protected/", protected_view),
    path("", include("config.urls")),
]

PRODUCTION_MIDDLEWARE = tuple(
    middleware for middleware in settings.MIDDLEWARE if not middleware.startswith("debug_toolbar.")
)


def _session_updates(queries: CaptureQueriesContext) -> list[str]:
    return [
        query["sql"]
        for query in queries.captured_queries
        if query["sql"].lstrip().upper().startswith("UPDATE") and "django_session" in query["sql"]
    ]


@override_settings(
    ROOT_URLCONF=__name__,
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_ALLOW_INSECURE_HTTP=True,
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class SessionActivityWriteTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        # After the suite's autouse fixture, which forces DEBUG=True and would undo a class override.
        self.enterContext(override_settings(DEBUG=False))
        platform = PlatformAPIClient()
        self.enterContext(patch("apps.users.middleware.api_client", platform))
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self._platform))

    def _platform(self, **kwargs: object) -> Response:
        response = Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps({"active": True, "membership_hash": "same"}).encode()
        return response

    def _client(self, last_activity: float | None) -> Client:
        client = Client(raise_request_exception=False)
        session = client.session
        now = timezone.now()
        session.update(
            {
                "user_id": 7,
                "customer_id": 42,
                "active_customer_id": 42,
                "email": "activity@example.com",
                "session_auth_hash": "current",
                "authenticated_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(hours=1)).isoformat(),
                "security_fingerprint": {
                    "ip_hash": hashlib.sha256(b"127.0.0.1").hexdigest()[:16],
                    "user_agent_hash": hashlib.sha256(b"").hexdigest()[:16],
                    "created_at": time.time(),
                },
            }
        )
        if last_activity is not None:
            session["last_activity"] = last_activity
        session.save()
        return client

    def _get(self, client: Client) -> tuple[HttpResponse, list[str]]:
        with CaptureQueriesContext(connection) as queries:
            response = client.get("/activity/protected/")
        return response, _session_updates(queries)

    def test_a_request_soon_after_the_last_stamp_does_not_rewrite_the_session(self) -> None:
        response, updates = self._get(self._client(last_activity=time.time() - 10))
        self.assertContains(response, MARKER)
        self.assertEqual(updates, [])

    def test_a_stamp_older_than_a_minute_is_refreshed(self) -> None:
        client = self._client(last_activity=time.time() - 61)
        before = time.time()
        response, updates = self._get(client)
        self.assertContains(response, MARKER)
        self.assertEqual(len(updates), 1)
        self.assertGreaterEqual(client.session["last_activity"], before)

    def test_a_session_without_a_stamp_gets_one_at_once(self) -> None:
        # Idle timeout reads a missing stamp as "now", so it must never stay missing.
        client = self._client(last_activity=None)
        response, updates = self._get(client)
        self.assertContains(response, MARKER)
        self.assertEqual(len(updates), 1)
        self.assertIn("last_activity", client.session)

    def test_an_idle_session_still_times_out(self) -> None:
        client = self._client(last_activity=time.time() - SessionSecurityMiddleware.SESSION_TIMEOUT_SECONDS - 1)
        key = client.session.session_key
        response, _updates = self._get(client)
        self.assertRedirects(response, "/login/?timeout=session_expired", fetch_redirect_response=False)
        self.assertFalse(Session.objects.filter(session_key=key).exists())
