"""H8: Session security middleware must invalidate session on internal error."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.db import DatabaseError
from django.http import HttpRequest, HttpResponse
from django.test import TestCase

from apps.common.middleware import SessionSecurityMiddleware

User = get_user_model()


class SessionSecurityFailClosedTests(TestCase):
    """H8: SessionSecurityMiddleware must flush session on error, not continue."""

    @patch("apps.common.middleware.SessionSecurityService")
    def test_session_flushed_on_security_service_error(self, mock_svc_class):
        mock_svc_class.update_session_timeout.side_effect = RuntimeError("Redis down")

        mw = SessionSecurityMiddleware(lambda r: HttpResponse("ok"))

        user = User.objects.create_user(email="sess-test@example.com", password="TestPass123!")
        request = HttpRequest()
        request.method = "GET"
        request.path = "/billing/invoices/"
        request.META["SERVER_NAME"] = "testserver"
        request.META["SERVER_PORT"] = "80"
        request.session = SessionStore()
        request.session.create()
        request.user = user
        session_key_before = request.session.session_key

        mw._process_session_security(request)

        # Session should have been flushed (key changed or emptied)
        self.assertNotEqual(request.session.session_key, session_key_before)

    @patch("apps.common.middleware.SessionSecurityService")
    def test_a_failed_invalidation_is_reported_rather_than_swallowed(self, mock_svc_class):
        """The CRITICAL above promises the session was invalidated. If it was not, say so.

        The flush used to run under `contextlib.suppress(Exception)`, so a session that could not be
        flushed left one log line claiming it had been invalidated "for safety" and the request
        carried on with a session a security check had just rejected. Revert the fix and this test
        fails: there is no second log line to find.
        """
        mock_svc_class.update_session_timeout.side_effect = RuntimeError("service down")
        mw = SessionSecurityMiddleware(lambda r: HttpResponse("ok"))

        user = User.objects.create_user(email="flush-fail@example.com", password="TestPass123!")
        request = HttpRequest()
        request.method = "GET"
        request.path = "/billing/invoices/"
        request.META["SERVER_NAME"] = "testserver"
        request.META["SERVER_PORT"] = "80"
        request.session = SessionStore()
        request.session.create()
        request.user = user

        with (
            patch.object(request.session, "flush", side_effect=DatabaseError("sessions table gone")),
            self.assertLogs("apps.common.middleware", level="CRITICAL") as logs,
        ):
            mw._process_session_security(request)

        self.assertTrue(
            any("Session invalidation FAILED" in line for line in logs.output),
            f"a failed flush must be logged as such; got {logs.output}",
        )

    @patch("apps.common.middleware.SessionSecurityService")
    def test_a_successful_invalidation_logs_no_failure(self, mock_svc_class):
        """The other direction, so the assertion above cannot pass by always logging."""
        mock_svc_class.update_session_timeout.side_effect = RuntimeError("service down")
        mw = SessionSecurityMiddleware(lambda r: HttpResponse("ok"))

        user = User.objects.create_user(email="flush-ok@example.com", password="TestPass123!")
        request = HttpRequest()
        request.method = "GET"
        request.path = "/billing/invoices/"
        request.META["SERVER_NAME"] = "testserver"
        request.META["SERVER_PORT"] = "80"
        request.session = SessionStore()
        request.session.create()
        request.user = user

        with self.assertLogs("apps.common.middleware", level="CRITICAL") as logs:
            mw._process_session_security(request)

        self.assertFalse(any("Session invalidation FAILED" in line for line in logs.output))
