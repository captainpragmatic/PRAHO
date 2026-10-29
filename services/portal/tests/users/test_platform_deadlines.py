"""The portal follows the deadlines Platform gave its session; it computes no lifetime of its own.

ADR-0017 section 5. The portal ends a session itself only at Platform's absolute end, which never
moves. Its stored idle deadline is a lower bound (activity moves Platform's without a validation),
so once it passes, the portal asks Platform before the request goes on, without failing open and
without counting the question as the customer's activity. Past the six-hour grace of an overdue
validation it asks Platform too, instead of ending the session unasked. Within the grace and
before the stored idle deadline, an outage still fails open as section 3 describes.

Every request goes through the production middleware and the production session store, with the
signed transport real and only Platform's answers faked.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import Mock, patch

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import Client, TestCase, override_settings
from django.urls import include, path
from django.utils import timezone
from requests import Response

from apps.api_client.services import PlatformAPIClient
from apps.common import counters

MARKER = "Signed-in view reached"
SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
PATH = "/deadlines/protected/"


def protected_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse(MARKER)


urlpatterns = [path("deadlines/protected/", protected_view), path("", include("config.urls"))]

PRODUCTION_MIDDLEWARE = tuple(m for m in settings.MIDDLEWARE if not m.startswith("debug_toolbar."))


@override_settings(
    ROOT_URLCONF=__name__,
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_ALLOW_INSECURE_HTTP=True,
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class PlatformDeadlineTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        # Off for hand-built sessions in the rest of the suite (conftest); this is the rule's own test.
        self.enterContext(override_settings(PORTAL_SESSION_DEADLINES_REQUIRED=True))
        platform = PlatformAPIClient()
        self.enterContext(patch("apps.users.middleware.api_client", platform))
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))
        self.validations: list[dict[str, Any]] = []
        self.answer: dict[str, Any] | None = {"active": True}  # None: Platform is down
        self.refused = False

    # ---- Platform -------------------------------------------------------------------------------

    def platform(self, **kwargs: Any) -> Response:
        url = str(kwargs["url"])
        response = Response()
        response.headers["Content-Type"] = "application/json"
        if url.endswith("/users/session/validate/"):
            self.validations.append(json.loads(kwargs["data"]))
            if self.answer is None:
                response.status_code, payload = 503, {"error": "unavailable"}
            elif self.refused:
                response.status_code, payload = 401, {"active": False, "error": "Session validation failed"}
            else:
                response.status_code, payload = 200, {"membership_hash": "h", **self.answer}
        elif url.endswith("/users/customers/"):
            response.status_code, payload = 200, {"success": True, "results": []}
        else:
            response.status_code, payload = 200, {"success": True}
        response._content = json.dumps(payload).encode()
        return response

    def platform_keeps_it_live(self, tier: str, idle: datetime, expires: datetime) -> None:
        self.answer = {
            "active": True,
            "session_tier": tier,
            "session_idle_deadline": idle.isoformat(),
            "session_expires_at": expires.isoformat(),
        }

    # ---- a signed-in browser ------------------------------------------------------------------

    def signed_in(  # noqa: PLR0913  # each clock of a session, set on its own
        self,
        tier: str = "standard",
        *,
        expires_in: timedelta = timedelta(hours=20),
        idle_in: timedelta = timedelta(minutes=50),
        validated_ago: timedelta = timedelta(0),
        next_validation_in: timedelta = timedelta(minutes=10),
        signed_in_ago: timedelta = timedelta(hours=1),
        quiet_for: timedelta | None = None,
        deadlines: bool = True,
    ) -> Client:
        client = Client()
        session = client.session
        now = timezone.now()
        session.update(
            {
                "user_id": 7,
                "customer_id": 42,
                "active_customer_id": 42,
                "email": "deadlines@example.com",
                "session_auth_hash": "current",
                "portal_session_id": SESSION_ID,
                "authenticated_at": (now - signed_in_ago).isoformat(),
                "session_created_at": (now - signed_in_ago).isoformat(),
                "validated_at": (now - validated_ago).isoformat(),
                "next_validate_at": (now + next_validation_in).isoformat(),
                # As the old idle clock stamped it: the last request, which a real session carries.
                "last_activity": time.time() - (validated_ago if quiet_for is None else quiet_for).total_seconds(),
                "security_fingerprint": {  # as login stamps it, for the test client's empty user agent
                    "browser": "other/other",
                    "user_agent_hash": hashlib.sha256(b"").hexdigest()[:16],
                    "created_at": time.time() - signed_in_ago.total_seconds(),
                },
            }
        )
        if deadlines:
            session.update(
                {
                    "session_tier": tier,
                    "session_expires_at": (now + expires_in).isoformat(),
                    "session_idle_deadline": (now + idle_in).isoformat(),
                }
            )
        session.save()
        return client

    def assert_continues(self, response: HttpResponse) -> None:
        self.assertEqual(response.status_code, 200, response.get("Location"))
        self.assertContains(response, MARKER)

    def assert_ended(self, response: HttpResponse, client: Client) -> None:
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])
        self.assertNotIn("user_id", client.session)

    # ---- the cases the old portal clocks got wrong ----------------------------------------------

    def test_a_remembered_session_back_after_two_idle_hours_continues_while_platform_says_so(self) -> None:
        client = self.signed_in(
            "remember",
            expires_in=timedelta(days=29),
            idle_in=timedelta(days=7) - timedelta(hours=2),
            validated_ago=timedelta(hours=2),
            next_validation_in=-timedelta(hours=2) + timedelta(minutes=12),
        )
        now = timezone.now()
        self.platform_keeps_it_live("remember", now + timedelta(days=7), now + timedelta(days=29))
        self.assert_continues(client.get(PATH))
        self.assertEqual(len(self.validations), 1)

    def test_an_active_standard_session_older_than_eight_hours_continues(self) -> None:
        client = self.signed_in(signed_in_ago=timedelta(hours=9), expires_in=timedelta(hours=15), quiet_for=timedelta(0))
        self.assert_continues(client.get(PATH))
        self.assertEqual(self.validations, [])  # nothing was due

    # ---- Platform's end ----------------------------------------------------------------------

    def test_the_end_platform_gave_ends_the_session_without_asking(self) -> None:
        for offset, live in ((timedelta(seconds=1), True), (timedelta(0), False), (-timedelta(seconds=1), False)):
            with self.subTest(offset=offset):
                self.validations.clear()
                # Idle and the next validation no sooner than the end, so only the end decides.
                client = self.signed_in(
                    expires_in=timedelta(hours=1), idle_in=timedelta(hours=1), next_validation_in=timedelta(hours=2)
                )
                end = datetime.fromisoformat(client.session["session_expires_at"])
                # Only the middleware's clock moves; the session row itself is still loaded.
                with patch("apps.users.middleware.django_timezone", Mock(now=Mock(return_value=end - offset))):
                    response = client.get(PATH)
                if live:
                    self.assert_continues(response)
                else:
                    self.assert_ended(response, client)
                self.assertEqual(self.validations, [])

    # ---- the stored idle deadline -------------------------------------------------------------

    def test_past_the_stored_idle_deadline_platform_is_asked_and_the_question_is_not_activity(self) -> None:
        client = self.signed_in(idle_in=-timedelta(seconds=1), validated_ago=timedelta(minutes=5))
        later = timezone.now() + timedelta(minutes=30)
        self.platform_keeps_it_live("standard", later, timezone.now() + timedelta(hours=19))
        self.assert_continues(client.get(PATH))
        (validation,) = self.validations
        self.assertIs(validation["interactive"], False)  # asking never extends Platform's idle deadline
        self.assertEqual(client.session["session_idle_deadline"], later.isoformat())  # refreshed

    def test_past_the_stored_idle_deadline_a_refusal_ends_the_session(self) -> None:
        client = self.signed_in(idle_in=-timedelta(seconds=1))
        self.refused = True
        self.assert_ended(client.get(PATH), client)

    def test_past_the_stored_idle_deadline_an_outage_ends_the_session_without_failing_open(self) -> None:
        client = self.signed_in(idle_in=-timedelta(seconds=1))
        self.answer = None
        self.assert_ended(client.get(PATH), client)
        self.assertEqual(counters.peek("auth:fail_open:7"), 0)  # the breaker was never consulted

    def test_an_answer_without_usable_deadlines_keeps_the_stored_ones(self) -> None:
        unusable = {"a word": "soon", "a list": ["standard"], "a dict": {"tier": "standard"}}
        for name, value in unusable.items():
            with self.subTest(value=name):
                self.validations.clear()
                client = self.signed_in(idle_in=-timedelta(seconds=1))
                stored = client.session["session_idle_deadline"]
                self.answer = {"active": True, "session_tier": value, "session_idle_deadline": value}
                self.assert_continues(client.get(PATH))  # Platform said the session lives
                self.assertEqual(client.session["session_idle_deadline"], stored)  # never extended on its own
                self.assertEqual(len(self.validations), 1)

    # ---- the hard grace -----------------------------------------------------------------------

    def test_past_the_hard_grace_platform_is_asked_instead_of_ending_the_session(self) -> None:
        client = self.signed_in(
            "remember",
            expires_in=timedelta(days=28),
            idle_in=timedelta(days=6),
            validated_ago=timedelta(hours=7, minutes=12),
            next_validation_in=-timedelta(hours=7),
        )
        now = timezone.now()
        self.platform_keeps_it_live("remember", now + timedelta(days=7), now + timedelta(days=28))
        self.assert_continues(client.get(PATH))
        self.assertEqual(len(self.validations), 1)

    def test_past_the_hard_grace_an_outage_ends_the_session(self) -> None:
        client = self.signed_in(
            "remember", idle_in=timedelta(days=6), validated_ago=timedelta(hours=7), next_validation_in=-timedelta(hours=7)
        )
        self.answer = None
        self.assert_ended(client.get(PATH), client)
        self.assertEqual(len(self.validations), 1)  # asked, and ended because Platform could not answer

    def test_control_within_the_grace_an_outage_still_fails_open(self) -> None:
        client = self.signed_in(
            validated_ago=timedelta(hours=1), next_validation_in=-timedelta(minutes=50), quiet_for=timedelta(0)
        )
        self.answer = None
        self.assert_continues(client.get(PATH))
        self.assertEqual(counters.peek("auth:fail_open:7"), 1)

    # ---- how an ended session answers each caller ----------------------------------------------

    def test_an_ended_session_answers_each_caller_in_a_form_it_can_follow(self) -> None:
        endings = {
            "Platform's end": {"expires_in": -timedelta(seconds=1), "idle_in": -timedelta(seconds=1)},
            "a refusal at the idle deadline": {"idle_in": -timedelta(seconds=1)},
        }
        for ending, clocks in endings.items():
            self.refused = ending.startswith("a refusal")
            with self.subTest(ending=ending, caller="htmx"):
                client = self.signed_in(**clocks)
                response = client.post(PATH, HTTP_HX_REQUEST="true", HTTP_HX_CURRENT_URL="http://testserver/billing/")
                self.assertEqual(response.status_code, 200)  # HTMX follows HX-Redirect, not a 302 it would swap in
                self.assertTrue(response["HX-Redirect"].startswith("/login/"))
                self.assertNotIn("user_id", client.session)
            with self.subTest(ending=ending, caller="fetch"):
                client = self.signed_in(**clocks)
                response = client.post(PATH, HTTP_ACCEPT="application/json")
                self.assertEqual(response.status_code, 401)
                self.assertEqual(json.loads(response.content), {"error": "Session ended", "redirect": "/login/"})
            with self.subTest(ending=ending, caller="page"):
                client = self.signed_in(**clocks)
                self.assert_ended(client.get(PATH), client)

    # ---- sessions without Platform's deadlines --------------------------------------------------

    def test_a_session_without_platform_s_deadlines_ends_once(self) -> None:
        client = self.signed_in(deadlines=False)
        self.assert_ended(client.get(PATH), client)
        self.assertEqual(self.validations, [])

    def test_control_the_rule_can_be_off_for_sessions_built_by_hand(self) -> None:
        with override_settings(PORTAL_SESSION_DEADLINES_REQUIRED=False):
            self.assert_continues(self.signed_in(deadlines=False).get(PATH))
