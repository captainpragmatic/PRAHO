"""A key rotation that gives up under contention reaches the session middleware's 503 (ADR-0055).

Login and two-factor setup rotate the session key inside a broad error handler. That handler must
let a contended rotation through, so the customer gets the portal's 503 with Retry-After instead of
an "unexpected error" page.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import RequestFactory, TestCase, override_settings

from apps.common.session_store import SessionSaveContended
from apps.users.views import _handle_totp_setup_post

PRODUCTION_MIDDLEWARE = tuple(m for m in settings.MIDDLEWARE if not m.startswith("debug_toolbar."))
CONTENDED = patch("apps.common.session_store.SessionStore.cycle_key", side_effect=SessionSaveContended("gave up"))


@override_settings(
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="apps.common.session_store",
    RATE_LIMITING_ENABLED=False,
    DEBUG=False,
)
class ContendedKeyRotationTests(TestCase):
    def test_login_answers_503_when_the_rotation_gives_up(self) -> None:
        client = self.client_class(raise_request_exception=False)
        with patch("apps.users.views.api_client") as platform, CONTENDED:
            platform.authenticate_customer.return_value = {"valid": True, "user_id": 123, "customer_id": 456}
            response = client.post("/login/", {"email": "test@example.com", "password": "pass123"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("Retry-After", response)

    def test_two_factor_setup_lets_a_contended_rotation_through(self) -> None:
        request = RequestFactory().post("/mfa/setup/totp/")
        request.session = MagicMock()
        request.session.cycle_key.side_effect = SessionSaveContended("gave up")
        with patch("apps.users.views.api_client") as platform:
            platform.verify_totp_mfa.return_value = {"success": True, "backup_codes": []}
            with self.assertRaises(SessionSaveContended):
                _handle_totp_setup_post(request, "456", "123456")
