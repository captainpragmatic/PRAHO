"""Fresh customer resolution and bounded membership revocation across independent sessions."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, JsonResponse
from django.test import Client, TestCase, override_settings
from django.urls import include, path
from django.utils import timezone
from requests import Response

from apps.api_client.services import PlatformAPIClient
from apps.common.decorators import require_customer_role


def context_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"active_customer_id": request.session.get("active_customer_id")})


def owner_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"owner_access": True})


urlpatterns = [
    path("wp7/context/", context_view),
    path("wp7/owner/", require_customer_role(["owner"])(owner_view)),
    path("", include("config.urls")),
]

PRODUCTION_MIDDLEWARE = tuple(
    middleware for middleware in settings.MIDDLEWARE if not middleware.startswith("debug_toolbar.")
)


@override_settings(
    ROOT_URLCONF=__name__,
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_ALLOW_INSECURE_HTTP=True,
    PLATFORM_API_READ_MAX_RETRIES=0,
    LANGUAGE_CODE="en",
)
class FreshCustomerMembershipTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.revoked = False
        self.customer_requests: list[str] = []
        self.platform_client = PlatformAPIClient()
        self.enterContext(patch("apps.users.middleware.api_client", self.platform_client))
        self.enterContext(patch("apps.common.decorators.api_client", self.platform_client))
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))

    def platform(self, **kwargs: object) -> Response:
        url = str(kwargs["url"])
        if url.endswith("/users/customers/"):
            self.customer_requests.append(url)
            payload: dict[str, object] = {
                "success": True,
                "results": [{"id": 43 if self.revoked else 42, "role": "owner", "name": "Company"}],
            }
        elif url.endswith("/users/session/validate/"):
            payload = {"active": True, "membership_hash": "after" if self.revoked else "before"}
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

    def client_for_user(self, fetched_at: float) -> Client:
        client = Client()
        now = timezone.now()
        session = client.session
        session.update(
            {
                "user_id": 7,
                "customer_id": 42,
                "email": "member@example.com",
                "session_auth_hash": "current",
                "authenticated_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(hours=1)).isoformat(),
                "membership_hash": "before",
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": fetched_at,
            }
        )
        session.save()
        return client

    def test_resolving_a_second_session_uses_current_membership_without_worker_cache(self) -> None:
        before = self.client_for_user(time.time())
        after = self.client_for_user(time.time())
        self.assertNotEqual(before.session.session_key, after.session.session_key)
        self.assertEqual(before.get("/wp7/context/").json(), {"active_customer_id": 42})
        self.revoked = True
        response = after.get("/wp7/context/")
        self.assertEqual(response.json(), {"active_customer_id": 43})
        self.assertEqual(len(self.customer_requests), 2)
        self.assertEqual(before.get("/wp7/context/").json(), {"active_customer_id": 42})
        self.assertEqual(after.get("/wp7/context/").json(), {"active_customer_id": 43})
        self.assertEqual(len(self.customer_requests), 2, "Resolved page views add no customer-list request")

    def test_second_session_observes_revocation_at_ttl_or_on_changed_hash(self) -> None:
        # Protected roles refresh on the first request after 300 s (strict > comparison).
        # A changed membership_hash invalidates roles at the next successful validation;
        # it can shorten the TTL bound, and does not add another 300 s waiting period.
        for mode in ("ttl", "hash"):
            with self.subTest(mode=mode):
                cache.clear()
                self.revoked = False
                started = time.time()
                clock = [started]
                with patch("django.core.cache.backends.locmem.time.time", side_effect=lambda clock=clock: clock[0]):
                    first = self.client_for_user(started)
                    second = self.client_for_user(started)
                    self.assertEqual(first.get("/wp7/owner/").json(), {"owner_access": True})
                    self.assertEqual(second.get("/wp7/owner/").json(), {"owner_access": True})
                    # An independently warmed worker cache must not extend session staleness.
                    cache.delete("user_customers_7")
                    clock[0] = started + 299
                    self.assertEqual(self.platform_client.get_user_customers(7)[0]["id"], 42)
                    self.revoked = True
                    clock[0] = started + (301 if mode == "ttl" else 299)
                    session = second.session
                    session.pop("active_customer_id", None)
                    if mode == "hash":
                        session["next_validate_at"] = (timezone.now() - timedelta(seconds=1)).isoformat()
                    session.save()
                    self.assertEqual(second.get("/wp7/context/").json(), {"active_customer_id": 43})
                    denied = second.get("/wp7/owner/", HTTP_ACCEPT="application/json")
                    self.assertEqual(denied.status_code, 403)
                    self.assertNotIn("owner_access", denied.json())
                    memberships = second.session["user_memberships"]
                    self.assertEqual([membership["customer_id"] for membership in memberships], [43])
                    if mode == "hash":
                        self.assertEqual(second.session["membership_hash"], "after")
