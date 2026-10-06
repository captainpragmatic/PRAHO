"""Authentication requests survive optional audit failures."""

from django.contrib.auth import authenticate, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory

from apps.users.models import User
from tests.common._signal_isolation import SignalIsolationTestCase


class AuthenticationSignalIsolationTests(SignalIsolationTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="auth-isolation@example.com", password="correct")
        self.request = RequestFactory().post("/auth/")
        SessionMiddleware(lambda request: HttpResponse()).process_request(self.request)
        self.request.session["keep"] = "before"

    def test_logout_request_survives_failed_audit_write(self) -> None:
        self.request.user = self.user

        def trigger() -> None:
            self.user.first_name = "Logged out"
            self.user.save(update_fields=["first_name"])
            logout(self.request)

        self.run_effect("apps.users.signals.AuthenticationAuditService.log_logout", trigger)
        self.assertEqual(User.objects.get(pk=self.user.pk).first_name, "Logged out")
        self.assertIsInstance(self.request.user, AnonymousUser)
        self.assertNotIn("keep", self.request.session)

    def test_failed_login_request_survives_failed_audit_write(self) -> None:
        self.request.user = AnonymousUser()

        def trigger() -> User | None:
            self.user.first_name = "Attempt recorded"
            self.user.save(update_fields=["first_name"])
            return authenticate(self.request, email=self.user.email, password="wrong")

        authenticated = self.run_effect("apps.users.signals.AuthenticationAuditService.log_login_failed", trigger)
        self.assertIsNone(authenticated)
        self.assertEqual(User.objects.get(pk=self.user.pk).first_name, "Attempt recorded")
