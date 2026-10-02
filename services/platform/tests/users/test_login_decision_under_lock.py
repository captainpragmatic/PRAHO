"""Login decisions are taken on the locked, freshly read user row.

Both the staff web login and the portal login read the account once in authenticate()
and then decided what to do from that copy. A change landing in between (2FA enrolment,
deactivation, a lockout, a password change) was missed: the web login could sign a
password-only session in for an account that had just enrolled, and the portal login
could accept an account that had just been deactivated or locked.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.contrib.auth import authenticate
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential

AccountChange = Callable[[User], None]


def enrol(user: User) -> None:
    User.objects.filter(pk=user.pk).update(two_factor_enabled=True)


def deactivate(user: User) -> None:
    User.objects.filter(pk=user.pk).update(is_active=False)


def lock(user: User) -> None:
    User.objects.filter(pk=user.pk).update(account_locked_until=timezone.now() + timedelta(minutes=5))


def change_password(user: User) -> None:
    fresh = User.objects.get(pk=user.pk)
    fresh.set_password("a-completely-different-password")
    fresh.save(update_fields=["password"])


def authenticate_then(module: str, change: AccountChange) -> Any:
    """Let authenticate() succeed, then change the account before the view decides."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        user = authenticate(*args, **kwargs)
        if user is not None:
            change(user)
        return user

    return patch(f"{module}.authenticate", side_effect=wrapper)


class StaffLoginDecisionTests(TestCase):
    def make_staff(self, email: str) -> User:
        return User.objects.create_user(email=email, password=PASSWORD, is_staff=True, staff_role="support")

    def login(self, client: Client, user: User, change: AccountChange) -> Any:
        with authenticate_then("apps.users.views", change):
            return client.post(reverse("users:login"), {"email": user.email, "password": PASSWORD})

    def test_enrolment_after_the_password_check_still_hands_off(self) -> None:
        user = self.make_staff("enrols-meanwhile@example.ro")
        client = Client()
        response = self.login(client, user, enrol)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("users:mfa_verify"))
        self.assertNotIn("_auth_user_id", client.session, "a password-only session for an enrolled account")

    def test_account_changes_after_the_password_check_refuse_the_login(self) -> None:
        for change in (deactivate, lock, change_password):
            with self.subTest(change.__name__):
                user = self.make_staff(f"{change.__name__}-meanwhile@example.ro")
                client = Client()
                response = self.login(client, user, change)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("_auth_user_id", client.session)
                self.assertNotIn("pre_2fa", client.session)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "decision"}},
)
class PortalLoginDecisionTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_account_changes_after_the_password_check_refuse_the_login(self) -> None:
        for change in (deactivate, lock, change_password):
            with self.subTest(change.__name__):
                user = User.objects.create_user(email=f"portal-{change.__name__}@example.ro", password=PASSWORD)
                with authenticate_then("apps.api.users.views", change):
                    response = self.portal_post("/api/users/login/", {"email": user.email, "password": PASSWORD})
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json(), {"success": False, "error": "Invalid email or password"})

    def test_enrolment_after_the_password_check_requires_the_code(self) -> None:
        user = User.objects.create_user(email="portal-enrols@example.ro", password=PASSWORD)
        with authenticate_then("apps.api.users.views", enrol):
            response = self.portal_post("/api/users/login/", {"email": user.email, "password": PASSWORD})
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(response.json(), {"success": False, "error": "Invalid authentication code"})

    def test_regression_guard_success_returns_the_locked_rows_hash(self) -> None:
        user = User.objects.create_user(email="portal-ok@example.ro", password=PASSWORD)
        User.objects.filter(pk=user.pk).update(failed_login_attempts=2)
        response = self.portal_post("/api/users/login/", {"email": user.email, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.content)
        fresh = User.objects.get(pk=user.pk)
        self.assertEqual(response.json()["session_auth_hash"], fresh.get_session_auth_hash())
        self.assertEqual(fresh.failed_login_attempts, 0)
