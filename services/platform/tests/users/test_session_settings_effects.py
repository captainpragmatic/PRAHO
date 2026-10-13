"""`users.admin_session_timeout_minutes` — the session window for admin and billing staff.

This file tested `users.shared_device_timeout_minutes`, the window of a shared-device mode that
nothing ever switched on; the mode and its setting are gone. The admin window is the session setting
that remains, and an operator who tightens it needs an admin's session to expire in that time.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest
from django.test import RequestFactory, TestCase, override_settings

from apps.settings.services import SettingsService
from apps.users.services import SessionSecurityService

ADMIN_TIMEOUT_KEY = "users.admin_session_timeout_minutes"
SECONDS_PER_MINUTE = 60
STANDARD_WINDOW = 3600

User = get_user_model()


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class AdminSessionTimeoutSettingEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()
        self.admin = User.objects.create_user(
            email="session-effect-admin@example.test", password="test-pass-1234", staff_role="admin"
        )
        self.customer = User.objects.create_user(email="session-effect@example.test", password="test-pass-1234")

    def set_value(self, minutes: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(ADMIN_TIMEOUT_KEY, minutes)
        self.assertTrue(result.is_ok(), result)

    def session_window(self, user: AbstractBaseUser) -> int:
        request: HttpRequest = self.factory.get("/")
        request.user = user
        SessionMiddleware(lambda _r: None).process_request(request)
        request.session.save()
        SessionSecurityService.update_session_timeout(request)
        return request.session.get_expiry_age()

    def test_a_tighter_window_shortens_an_admin_session_and_a_looser_one_lengthens_it(self) -> None:
        """One assertion in each direction, so a hardcoded constant cannot satisfy both."""
        self.set_value(10)
        tight = self.session_window(self.admin)
        self.set_value(90)
        loose = self.session_window(self.admin)

        self.assertEqual(tight, 10 * SECONDS_PER_MINUTE)
        self.assertEqual(loose, 90 * SECONDS_PER_MINUTE)

    def test_the_catalog_default_applies_when_nothing_is_stored(self) -> None:
        expected = int(SettingsService.DEFAULT_SETTINGS[ADMIN_TIMEOUT_KEY]) * SECONDS_PER_MINUTE

        self.assertEqual(self.session_window(self.admin), expected)

    def test_the_window_applies_only_to_admin_and_billing_staff(self) -> None:
        self.set_value(10)

        self.assertEqual(self.session_window(self.customer), STANDARD_WINDOW)
