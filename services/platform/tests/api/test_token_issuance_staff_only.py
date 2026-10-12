"""API tokens are issued to staff accounts only (#621).

ADR-0031 issues tokens to operator scripts and CLI tools through dedicated staff service
accounts, and the page that manages them is staff-only. `POST /api/users/token/` checked
only the email, the password and the second factor, so any customer account could mint
one. A customer is now refused with the wrong-password body. The check runs before the
second factor, so the refusal neither spends a code nor counts against the account, and
it runs again on the locked row, so a demotion during the request is not skipped.

`GET /api/users/token/verify/` answered with the customer's first member rather than the
caller, so it reported another person's email and staff flag. Nothing called it, and
`token/me/` covers introspection, so it is gone.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pyotp
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.db.models import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import NoReverseMatch, Resolver404, resolve, reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.users.mfa import TOTPService
from apps.users.models import APIToken, User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
WRONG_PASSWORD = "definitely-not-the-password"  # test fixture, not a credential
REFUSED = (401, {"error": "Invalid credentials"})


def failed_logins() -> QuerySet[AuditEvent]:
    return AuditEvent.objects.filter(action__startswith="login_failed")


# The endpoint's throttles are live in production; they need a real cache to count against.
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=True,
)
class TokenIssuanceStaffOnlyTests(TestCase):
    url = "/api/users/token/"

    def setUp(self) -> None:
        cache.clear()  # throttle buckets are cache-backed and leak between tests
        self.addCleanup(cache.clear)

    def post(self, email: str, password: str = PASSWORD, **extra: str) -> tuple[int, dict[str, object]]:
        body = {"email": email, "password": password, **extra}
        response = self.client.post(self.url, body, content_type="application/json")
        return response.status_code, response.json()

    def test_customer_with_correct_password_is_refused_like_a_wrong_password(self) -> None:
        customer = User.objects.create_user(email="customer@example.ro", password=PASSWORD)

        refused = self.post(customer.email)
        wrong_password = self.post(customer.email, password=WRONG_PASSWORD)

        self.assertEqual(refused, REFUSED)
        # Identical to a wrong password, so the endpoint does not reveal which accounts are staff.
        self.assertEqual(refused, wrong_password)
        self.assertFalse(APIToken.objects.filter(user=customer).exists())
        customer.refresh_from_db()
        self.assertEqual(customer.failed_login_attempts, 0)

    def test_customer_gate_runs_before_second_factor(self) -> None:
        customer = User.objects.create_user(email="mfa-customer@example.ro", password=PASSWORD)
        customer.two_factor_secret = TOTPService.generate_secret()
        customer.two_factor_enabled = True
        customer.save()

        # A wrong code counts against the account when the second factor runs (see
        # test_token_endpoint_second_factor.py). Zero here means it never ran for a customer.
        self.assertEqual(self.post(customer.email, mfa_token="000000"), REFUSED)
        customer.refresh_from_db()
        self.assertEqual(customer.failed_login_attempts, 0)

        # A valid code is refused too, and no token exists.
        valid = pyotp.TOTP(customer.two_factor_secret).now()
        self.assertEqual(self.post(customer.email, mfa_token=valid), REFUSED)
        self.assertFalse(APIToken.objects.filter(user=customer).exists())

        # A backup code offered with the refused request is not spent.
        backup_code = customer.generate_backup_codes()[0]
        self.assertEqual(self.post(customer.email, mfa_token=backup_code), REFUSED)
        customer.refresh_from_db()
        self.assertEqual(len(customer.backup_tokens), 8)
        self.assertTrue(customer.verify_backup_code(backup_code))

    def test_customer_refusal_is_audited_like_a_wrong_password(self) -> None:
        """Both refusals write one failed-login audit row, so neither does less work than the other."""
        customer = User.objects.create_user(email="audited-customer@example.ro", password=PASSWORD)

        self.post(customer.email, password=WRONG_PASSWORD)
        self.assertEqual(failed_logins().count(), 1)

        self.post(customer.email)
        self.assertEqual(failed_logins().count(), 2)
        refusal = failed_logins().latest("timestamp")
        self.assertEqual(refusal.metadata["failure_reason"], "not_staff")
        self.assertEqual(refusal.metadata["login_method"], "api_token")

    def test_locked_account_refusal_is_audited_like_a_wrong_password(self) -> None:
        """The other refusal that follows a correct password leaves the same trace."""
        staff = User.objects.create_user(email="locked-staff@example.ro", password=PASSWORD, staff_role="support")
        staff.account_locked_until = timezone.now() + timedelta(minutes=30)
        staff.save(update_fields=["account_locked_until"])

        self.assertEqual(self.post(staff.email), REFUSED)

        self.assertEqual(failed_logins().count(), 1)
        self.assertEqual(failed_logins().get().metadata["failure_reason"], "account_locked")
        staff.refresh_from_db()
        self.assertEqual(staff.failed_login_attempts, 0)

    def test_every_kind_of_staff_account_is_issued_a_token(self) -> None:
        accounts = {
            "staff role only": {"staff_role": "support"},
            "Django staff flag only": {"is_staff": True},
            "superuser flag only": {"is_superuser": True},
        }
        for index, (kind, flags) in enumerate(accounts.items()):
            with self.subTest(kind):
                user = User.objects.create_user(email=f"staff-{index}@example.ro", password=PASSWORD, **flags)
                status_code, payload = self.post(user.email)
                self.assertEqual(status_code, 200, payload)
                self.assertEqual(payload["user_id"], user.id)
                self.assertEqual(APIToken.objects.filter(user=user).count(), 1)

    def authenticate_then(self, change: Callable[[], None]) -> Any:
        """Run the real password check, then change the account before issuance continues."""

        def side_effect(*args: Any, **kwargs: Any) -> Any:
            result = authenticate(*args, **kwargs)
            change()
            return result

        return patch("apps.api.users.views.authenticate", side_effect=side_effect)

    def test_demotion_after_authenticate_is_refused_under_lock(self) -> None:
        staff = User.objects.create_user(email="leaving@example.ro", password=PASSWORD, staff_role="support")

        def demote() -> None:
            User.objects.filter(pk=staff.pk).update(staff_role="", is_staff=False, is_superuser=False)

        with self.authenticate_then(demote):
            self.assertEqual(self.post(staff.email), REFUSED)
        self.assertFalse(APIToken.objects.filter(user=staff).exists())
        # It followed a correct password too, so it leaves the same failed-login trace.
        self.assertEqual(failed_logins().count(), 1)
        self.assertEqual(failed_logins().get().metadata["failure_reason"], "account_changed")


class TokenVerifyRouteRemovedTests(SimpleTestCase):
    def test_token_verify_route_is_gone(self) -> None:
        # Resolution, not an HTTP status: in production an unsigned request to an unknown /api/
        # path gets the HMAC middleware's 401, which the test settings leave out.
        with self.assertRaises(NoReverseMatch):
            reverse("api:verify_token")
        with self.assertRaises(Resolver404):
            resolve("/api/users/token/verify/")
