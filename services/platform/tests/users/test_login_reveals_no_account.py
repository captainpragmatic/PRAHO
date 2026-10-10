"""A failed login gives no sign of whether the email belongs to an account.

Every non-MFA failure - unknown email, wrong password, inactive or locked account - must get the
same answer, and no failure path may behave differently only because an account exists: the
staff login used to report "Account temporarily locked" (and skip the password hash) for a
locked account, and both login paths could answer a 500 when the failed-attempt write - which
runs only for real accounts - hit a database error.
"""

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.db import OperationalError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.users import views as user_views
from apps.users.models import User, UserLoginLog
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "Correct-horse-battery-9"
WRONG = "Wrong-horse-battery-9"
UNIFORM_API_REFUSAL = {"success": False, "error": "Invalid email or password"}
UNIFORM_STAFF_REFUSAL = "Incorrect email or password."


def _locked(user: User) -> User:
    User.objects.filter(pk=user.pk).update(
        account_locked_until=timezone.now() + timedelta(minutes=30), failed_login_attempts=5
    )
    return User.objects.get(pk=user.pk)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    DISABLE_ACCOUNT_LOCKOUT=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "reveals-none"}},
)
class PortalLoginRevealsNoAccountTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def _attempt(self, email: str, password: str) -> Any:
        return self.portal_post("/api/users/login/", {"email": email, "password": password})

    def test_every_non_mfa_failure_is_the_same_answer(self) -> None:
        real = User.objects.create_user(email="real@example.ro", password=PASSWORD)
        inactive = User.objects.create_user(email="inactive@example.ro", password=PASSWORD, is_active=False)
        locked = _locked(User.objects.create_user(email="locked@example.ro", password=PASSWORD))
        attempts = {
            "unknown email": ("nobody@example.ro", PASSWORD),
            "wrong password": (real.email, WRONG),
            "inactive, right password": (inactive.email, PASSWORD),
            "inactive, wrong password": (inactive.email, WRONG),
            "locked, right password": (locked.email, PASSWORD),
            "locked, wrong password": (locked.email, WRONG),
        }
        answers = {}
        for case, (email, password) in attempts.items():
            with self.subTest(case=case):
                response = self._attempt(email, password)
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json(), UNIFORM_API_REFUSAL)
                answers[case] = (response.status_code, response.content, tuple(sorted(response.headers.items())))
        self.assertEqual(len(set(answers.values())), 1, answers)

    def test_a_failed_attempt_write_failure_still_answers_the_uniform_refusal(self) -> None:
        # The counter write runs only for a real account. A 500 there was a sign only real emails give.
        real = User.objects.create_user(email="real-write-fails@example.ro", password=PASSWORD)
        with (
            patch.object(User, "increment_failed_login_attempts", side_effect=OperationalError("db down")),
            patch("apps.api.users.views._charge_login_failure") as charge,
        ):
            response = self._attempt(real.email, WRONG)
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(response.json(), UNIFORM_API_REFUSAL)
        charge.assert_called_once()  # the forwarded-IP failure budget is still charged

    def test_a_locked_account_does_not_extend_its_lock_from_more_attempts(self) -> None:
        # Otherwise anyone who knows an address could keep that account locked out from the portal.
        locked = _locked(User.objects.create_user(email="api-still-locked@example.ro", password=PASSWORD))
        before = (locked.failed_login_attempts, locked.account_locked_until)
        response = self._attempt(locked.email, WRONG)
        self.assertEqual(response.status_code, 401, response.content)
        locked.refresh_from_db()
        self.assertEqual((locked.failed_login_attempts, locked.account_locked_until), before)


@override_settings(DISABLE_ACCOUNT_LOCKOUT=False)
class StaffLoginRevealsNoAccountTests(TestCase):
    def _attempt(self, email: str, password: str) -> tuple[int, list[str], bool]:
        client = Client()
        response = client.post(reverse("users:login"), {"email": email, "password": password})
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        return response.status_code, messages, "_auth_user_id" in client.session

    def _staff(self, email: str, **extra: Any) -> User:
        return User.objects.create_user(email=email, password=PASSWORD, is_staff=True, staff_role="admin", **extra)

    def test_every_failure_is_the_same_answer_and_does_the_same_work(self) -> None:
        real = self._staff("staff-real@example.ro")
        inactive = self._staff("staff-inactive@example.ro", is_active=False)
        locked = _locked(self._staff("staff-locked@example.ro"))
        locked_customer = _locked(User.objects.create_user(email="customer-locked@example.ro", password=PASSWORD))
        attempts = {
            "unknown email": ("nobody@example.ro", PASSWORD),
            "wrong password": (real.email, WRONG),
            "inactive, right password": (inactive.email, PASSWORD),
            "locked, right password": (locked.email, PASSWORD),
            "locked, wrong password": (locked.email, WRONG),
            # A locked customer with the right password must not reach the "customers use the
            # portal" redirect: that would confirm the password during the lockout.
            "locked customer, right password": (locked_customer.email, PASSWORD),
            "locked customer, wrong password": (locked_customer.email, WRONG),
        }
        for case, (email, password) in attempts.items():
            with self.subTest(case=case), patch.object(user_views, "authenticate", wraps=user_views.authenticate) as checked:
                logs, audits = UserLoginLog.objects.count(), AuditEvent.objects.count()
                status, messages, logged_in = self._attempt(email, password)
                self.assertEqual((status, messages, logged_in), (200, [UNIFORM_STAFF_REFUSAL], False))
                # The password is hashed for every email: a locked account must not answer faster.
                checked.assert_called_once()
                # And every refusal writes the same records: one login log row, one audit event.
                written = (UserLoginLog.objects.count() - logs, AuditEvent.objects.count() - audits)
                self.assertEqual(written, (1, 1))

    def test_a_locked_account_given_the_right_password_is_recorded(self) -> None:
        # authenticate() succeeds, so no login-failed signal fires; the strongest sign of an
        # account under attack must still leave a trace.
        locked = _locked(self._staff("staff-locked-right@example.ro"))
        self._attempt(locked.email, PASSWORD)
        self.assertEqual(
            list(UserLoginLog.objects.filter(user=locked).values_list("status", flat=True)), ["account_locked"]
        )

    def test_a_locked_account_does_not_extend_its_lock_from_more_attempts(self) -> None:
        locked = _locked(self._staff("staff-still-locked@example.ro"))
        before = (locked.failed_login_attempts, locked.account_locked_until)
        self._attempt(locked.email, WRONG)
        locked.refresh_from_db()
        self.assertEqual((locked.failed_login_attempts, locked.account_locked_until), before)

    def test_a_failed_attempt_write_failure_still_answers_the_uniform_refusal(self) -> None:
        real = self._staff("staff-write-fails@example.ro")
        with patch.object(User, "increment_failed_login_attempts", side_effect=OperationalError("db down")):
            status, messages, logged_in = self._attempt(real.email, WRONG)
        self.assertEqual((status, messages, logged_in), (200, [UNIFORM_STAFF_REFUSAL], False))
