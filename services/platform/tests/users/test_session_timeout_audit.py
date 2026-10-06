"""The session timeout is audited when it changes, not on every authenticated request (#553).

`SessionSecurityMiddleware` calls `update_session_timeout` on every authenticated
request in production and staging. Logging `session_timeout_updated` unconditionally
wrote one audit row per request. The middleware is absent from `config/settings/test.py`,
so the default suite never saw it; the end-to-end test below adds it back.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.users.models import User
from apps.users.services import SessionSecurityService

TIMEOUT_EVENT = "session_timeout_updated"


def _timeout_calls(mock_log: MagicMock) -> int:
    return sum(call.args[0] == TIMEOUT_EVENT for call in mock_log.call_args_list)


class SessionTimeoutAuditTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="timeout-audit@example.com", password="Timeout-password123!")
        self.factory = RequestFactory()

    def _request(self) -> HttpRequest:
        request = self.factory.get("/")
        SessionMiddleware(lambda r: HttpResponse()).process_request(request)
        request.session.save()
        request.user = self.user
        return request

    @patch("apps.users.services.log_security_event")
    def test_an_unchanged_timeout_is_logged_once(self, mock_log: MagicMock) -> None:
        """FAILS on master: the second, identical call logs again."""
        request = self._request()

        SessionSecurityService.update_session_timeout(request)
        SessionSecurityService.update_session_timeout(request)

        self.assertEqual(_timeout_calls(mock_log), 1)

    @patch("apps.users.services.log_security_event")
    def test_a_changed_timeout_is_logged_again(self, mock_log: MagicMock) -> None:
        """Guard: switching to shared-device mode changes the timeout, so it is logged."""
        request = self._request()
        SessionSecurityService.update_session_timeout(request)

        request.session["shared_device_mode"] = True
        SessionSecurityService.update_session_timeout(request)

        self.assertEqual(_timeout_calls(mock_log), 2)

    @override_settings(SESSION_COOKIE_AGE=3600)
    @patch("apps.users.services.log_security_event")
    def test_the_first_timeout_is_logged_when_it_equals_the_cookie_age(self, mock_log: MagicMock) -> None:
        """Guard: production's cookie age (3600) equals the standard policy (3600).

        Comparing against `get_expiry_age()`, which falls back to SESSION_COOKIE_AGE, would
        see no change on the first request and never log the timeout a session starts with.
        """
        request = self._request()

        SessionSecurityService.update_session_timeout(request)

        self.assertEqual(SessionSecurityService.get_appropriate_timeout(request), 3600)
        self.assertEqual(_timeout_calls(mock_log), 1)


@override_settings(MIDDLEWARE=[*settings.MIDDLEWARE, "apps.common.middleware.SessionSecurityMiddleware"])
class SessionTimeoutAuditThroughMiddlewareTests(TestCase):
    """End to end through the middleware production runs on every authenticated request."""

    def test_two_requests_write_one_timeout_audit_row(self) -> None:
        """FAILS on master: every authenticated request inserts an audit row."""
        user = User.objects.create_user(email="timeout-mw@example.com", password="Timeout-password123!")
        self.client.force_login(user)

        self.client.get("/")
        self.client.get("/")

        self.assertEqual(AuditEvent.objects.filter(action=TIMEOUT_EVENT).count(), 1)
