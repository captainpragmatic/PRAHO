"""A login asks Platform for the session the person chose, and keeps the deadlines Platform answers.

The "remember me" box travels to Platform as a signed boolean; Platform decides the tier (staff never
get the remembered one). The portal signs in only with deadlines that can be Platform's, and stores
them as Platform gave them (ADR-0017 section 5).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from tests.helpers.platform_login import session_fields


@override_settings(RATE_LIMITING_ENABLED=False)
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
