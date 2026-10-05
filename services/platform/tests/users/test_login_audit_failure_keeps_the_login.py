"""PostgreSQL proof that a failing login audit write cannot undo the login around it.

login() runs inside the transaction that decided it, and fires user_logged_in, whose audit
handler swallows its own errors so auditing never blocks a sign-in. On PostgreSQL a failed
statement aborts the whole transaction, so a swallowed database error with no savepoint
around it left every later query failing ("current transaction is aborted") and the login
bookkeeping rolled back. The handler now writes inside its own savepoint. SQLite does not
abort a transaction on a failed statement, so only PostgreSQL can show this.
"""

from __future__ import annotations

from unittest.mock import patch

from django.db import connection
from django.test import TransactionTestCase
from django.urls import reverse

from apps.users.models import User, UserLoginLog

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


def _failing_audit_write(*_args: object, **_kwargs: object) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 / 0")  # a real database error, raised by PostgreSQL


class LoginAuditFailureKeepsTheLoginTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("only PostgreSQL aborts a transaction on a failed statement")
        self.user = User.objects.create_user(
            email="audit-failure@example.test", password=PASSWORD, is_staff=True, staff_role="support"
        )

    def test_a_database_error_in_the_login_audit_does_not_undo_the_login(self) -> None:
        with patch(
            "apps.users.signals.AuthenticationAuditService.log_login_success", side_effect=_failing_audit_write
        ) as audit:
            response = self.client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})

        self.assertTrue(audit.called, "the audit handler never ran, so this proves nothing")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("dashboard"))
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        self.assertTrue(UserLoginLog.objects.filter(user=self.user, status="success").exists())
