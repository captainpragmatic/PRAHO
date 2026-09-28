"""`users.shared_device_timeout_minutes` — the session window on a shared machine.

The setting had no test that mentioned it. `test_session_management.py` asserts
`get_expiry_age() == 900`, which pins the value 15 minutes produces but never writes the setting, so
it would keep passing if `_get_timeout_policies` stopped reading the setting entirely. That is the
difference this file exists to close: a shorter window is the entire security purpose of shared-device
mode, and an operator who tightens it to 5 minutes needs the session to actually expire in 5.

`users.admin_session_timeout_minutes` is asserted alongside it, because the two are read in the same
method and a mix-up between them would hand staff the shared-device window or vice versa - a
plausible failure that no assertion on one setting alone could catch.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest
from django.test import RequestFactory, TestCase, override_settings

from apps.settings.services import SettingsService
from apps.users.services import SessionSecurityService

SHARED_DEVICE_KEY = "users.shared_device_timeout_minutes"
ADMIN_TIMEOUT_KEY = "users.admin_session_timeout_minutes"
SECONDS_PER_MINUTE = 60

User = get_user_model()


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class SessionTimeoutSettingEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = RequestFactory()
        self.user = User.objects.create_user(email="session-effect@example.test", password="test-pass-1234")

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def authenticated_request(self) -> HttpRequest:
        request = self.factory.get("/")
        request.user = self.user
        SessionMiddleware(lambda _r: None).process_request(request)
        request.session.save()
        return request

    def test_the_configured_window_is_the_one_the_session_gets(self) -> None:
        self.set_value(SHARED_DEVICE_KEY, 5)
        request = self.authenticated_request()

        SessionSecurityService.enable_shared_device_mode(request)

        self.assertTrue(request.session.get("shared_device_mode"))
        self.assertEqual(request.session.get_expiry_age(), 5 * SECONDS_PER_MINUTE)

    def test_a_tighter_window_shortens_the_session_and_a_looser_one_lengthens_it(self) -> None:
        """One assertion in each direction, so a hardcoded constant cannot satisfy both."""
        self.set_value(SHARED_DEVICE_KEY, 2)
        tight = self.authenticated_request()
        SessionSecurityService.enable_shared_device_mode(tight)

        self.set_value(SHARED_DEVICE_KEY, 45)
        loose = self.authenticated_request()
        SessionSecurityService.enable_shared_device_mode(loose)

        self.assertEqual(tight.session.get_expiry_age(), 2 * SECONDS_PER_MINUTE)
        self.assertEqual(loose.session.get_expiry_age(), 45 * SECONDS_PER_MINUTE)

    def test_the_catalog_default_applies_when_nothing_is_stored(self) -> None:
        request = self.authenticated_request()

        SessionSecurityService.enable_shared_device_mode(request)

        expected = int(SettingsService.DEFAULT_SETTINGS[SHARED_DEVICE_KEY]) * SECONDS_PER_MINUTE
        self.assertEqual(request.session.get_expiry_age(), expected)

    def test_the_two_session_settings_are_not_crossed(self) -> None:
        """Both are read in `_get_timeout_policies`; swapping them would pass a one-setting test."""
        self.set_value(SHARED_DEVICE_KEY, 3)
        self.set_value(ADMIN_TIMEOUT_KEY, 90)

        policies = SessionSecurityService._get_timeout_policies()

        self.assertEqual(policies["shared_device"], 3 * SECONDS_PER_MINUTE)
        self.assertEqual(policies["sensitive"], 90 * SECONDS_PER_MINUTE)

    def test_an_unauthenticated_request_gets_no_shared_device_window(self) -> None:
        """The guard the service opens with, pinned so the effect tests cannot mask its removal."""
        self.set_value(SHARED_DEVICE_KEY, 5)
        request = self.factory.get("/")
        SessionMiddleware(lambda _r: None).process_request(request)
        request.user = AnonymousUser()

        SessionSecurityService.enable_shared_device_mode(request)

        self.assertIsNone(request.session.get("shared_device_mode"))
