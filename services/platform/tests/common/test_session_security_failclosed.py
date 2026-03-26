"""H8: Session security middleware must invalidate session on internal error."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
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
