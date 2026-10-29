"""A login asks Platform for the session the person chose, and keeps the deadlines Platform answers.

The "remember me" box travels to Platform as a signed boolean; Platform decides the tier (staff never
get the remembered one). The portal signs in only with deadlines that can be Platform's, and stores
them as Platform gave them (ADR-0017 section 5).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.contrib.sessions.models import Session
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.common.session_store import SessionStore
from tests.helpers.platform_login import session_fields


@override_settings(RATE_LIMITING_ENABLED=False, SESSION_ENGINE="apps.common.session_store")
class LoginSessionTierTests(TestCase):
    def sign_in(self, answer: dict[str, Any], **form: str) -> tuple[Any, Any]:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
                "session_id": str(uuid4()),
                **answer,
            }
            platform.post.return_value = {"success": True, "results": [{"id": 456, "name": "Acme", "role": "owner"}]}
            platform.get_customer_profile.return_value = {"first_name": "Ana"}
            response = self.client.post(
                reverse("users:login"), {"email": "ana@example.ro", "password": "pass123", **form}
            )
        return response, platform

    def test_the_box_is_sent_to_platform(self) -> None:
        for form, sent in (({"remember_me": "on"}, True), ({}, False)):
            with self.subTest(remember=sent):
                self.client = self.client_class()  # signed out again
                _response, platform = self.sign_in(session_fields(), **form)
                self.assertIs(platform.authenticate_customer.call_args.kwargs["remember_me"], sent)

    def test_the_window_login_opened_is_kept_to_be_echoed(self) -> None:
        window = "2026-10-29T18:00:00.123456+00:00"
        response, _platform = self.sign_in({**session_fields(), "step_up_at": window})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["step_up_at"], window)

    def test_platform_s_deadlines_are_stored_as_given(self) -> None:
        answer = session_fields("remember")
        response, _platform = self.sign_in(answer, remember_me="on")
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        for key, value in answer.items():
            self.assertEqual(session[key], value)

    def test_a_login_without_deadlines_platform_could_give_is_not_a_login(self) -> None:
        now = timezone.now()
        answers = {
            "none at all": {},
            "an unknown tier": {**session_fields(), "session_tier": "forever"},
            "an end months away": {**session_fields(), "session_expires_at": (now + timedelta(days=90)).isoformat()},
            "a naive time": {**session_fields(), "session_idle_deadline": (now + timedelta(hours=1)).replace(tzinfo=None).isoformat()},
        }
        for name, answer in answers.items():
            with self.subTest(answer=name):
                self.client = self.client_class()  # signed out again
                response, _platform = self.sign_in(answer)
                self.assertNotEqual(response.status_code, 302)
                self.assertNotIn("user_id", self.client.session)
                self.assertNotIn("portal_session_id", self.client.session)

    def test_the_cookie_lives_as_platform_s_session_and_its_row_ends_at_platform_s_end(self) -> None:
        for tier in ("standard", "remember"):
            with self.subTest(tier=tier):
                self.client = self.client_class()
                answer = session_fields(tier)
                response, _platform = self.sign_in(answer, **({"remember_me": "on"} if tier == "remember" else {}))
                cookie = response.cookies[settings.SESSION_COOKIE_NAME]
                end = datetime.fromisoformat(answer["session_expires_at"])
                if tier == "remember":
                    self.assertAlmostEqual(int(cookie["max-age"]), (end - timezone.now()).total_seconds(), delta=5)
                else:
                    self.assertEqual(cookie["max-age"], "")  # ends with the browser
                row = Session.objects.get(session_key=cookie.value)
                self.assertEqual(row.expire_date, end)
                # A later save, by any request of this session, keeps that end.
                later = SessionStore(cookie.value)
                later["selected_customer_id"] = 456
                later.save()
                self.assertEqual(Session.objects.get(session_key=cookie.value).expire_date, end)

    def test_a_row_never_outlives_platform_s_end_whatever_expiry_the_session_carries(self) -> None:
        end = timezone.now() + timedelta(hours=1)
        store = SessionStore()
        store.update({"user_id": 7, "session_tier": "standard", "session_expires_at": end.isoformat()})
        store.set_expiry(30 * 24 * 60 * 60)  # what a login before the tiers set: a 30-day cookie age
        store.save()
        self.assertEqual(Session.objects.get(session_key=store.session_key).expire_date, end)
        later = SessionStore(store.session_key)
        later["selected_customer_id"] = 456
        later.save()
        self.assertEqual(Session.objects.get(session_key=store.session_key).expire_date, end)
