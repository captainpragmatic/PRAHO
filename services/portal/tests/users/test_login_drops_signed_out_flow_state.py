"""Signing in drops what the signed-out recovery and registration flows left in the session.

Login rotates the session key but keeps its data, so a password-reset link or a registration
confirmation link opened before signing in stayed in the signed-in session, usable by anyone who
later held that session. The registration form's prefill and intent stayed too, though only the
signed-out registration page reads them. The visit's attribution, which every order carries, stays.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.users.constants import (
    ATTRIBUTION_SESSION_KEY,
    PASSWORD_RESET_SESSION_KEY,
    REGISTRATION_CONFIRM_SESSION_KEY,
    REGISTRATION_INTENT_SESSION_KEY,
    REGISTRATION_PREFILL_SESSION_KEY,
)

LEFT_BY_SIGNED_OUT_FLOWS = (
    PASSWORD_RESET_SESSION_KEY,
    REGISTRATION_CONFIRM_SESSION_KEY,
    REGISTRATION_PREFILL_SESSION_KEY,
    REGISTRATION_INTENT_SESSION_KEY,
)


@override_settings(RATE_LIMITING_ENABLED=False)
class LoginDropsSignedOutFlowStateTests(TestCase):
    def _open_the_links(self) -> None:
        """Open each emailed or staff-minted link the way a signed-out visitor does."""
        self.client.get(reverse("users:password_reset_link", args=["MTIz", "reset-token"]))
        self.client.get(reverse("users:register_confirm_link", args=[uuid4(), "confirm-token"]))
        with patch("apps.users.views.api_client") as platform:
            platform.read_registration_prefill.return_value = {
                "prefill": {"fields": {"company_name": "Acme SRL"}, "intent": {"product": "web-starter"}}
            }
            self.client.get(reverse("users:register"), {"p": "prefill-token", "utm_source": "newsletter"})

    def _sign_in(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.authenticate_customer.return_value = {
                "valid": True,
                "user_id": 123,
                "customer_id": 456,
                "session_id": str(uuid4()),  # Platform opens the session (ADR-0017 section 5)
            }
            platform.post.return_value = {"success": True, "results": [{"id": 456, "name": "Acme", "role": "owner"}]}
            platform.get_customer_profile.return_value = {"first_name": "Ana"}
            response = self.client.post(reverse("users:login"), {"email": "ana@example.ro", "password": "pass123"})
        self.assertEqual(response.status_code, 302)

    def test_signing_in_drops_the_links_and_registration_details(self) -> None:
        self._open_the_links()
        for key in (*LEFT_BY_SIGNED_OUT_FLOWS, ATTRIBUTION_SESSION_KEY):
            self.assertIn(key, self.client.session, key)  # each flow really left its state
        self._sign_in()
        session = self.client.session
        self.assertEqual(session["user_id"], 123)
        self.assertEqual([key for key in LEFT_BY_SIGNED_OUT_FLOWS if key in session], [])

    def test_control_the_visit_attribution_survives_signing_in(self) -> None:
        self._open_the_links()
        self._sign_in()
        self.assertEqual(self.client.session[ATTRIBUTION_SESSION_KEY], {"utm_source": "newsletter"})
