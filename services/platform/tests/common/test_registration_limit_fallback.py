"""Configured decorator limits survive malformed registration settings."""

from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase

from apps.common import counters
from apps.common.security_decorators import SecurityConfig, secure_service_method
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class RegistrationLimitFallbackTests(TestCase):
    def test_malformed_registration_setting_preserves_custom_limit_and_blocks_second_attempt(self) -> None:
        key = "security.registration_rate_limit_per_ip"
        stored = SettingsService.update_setting(key, 5)
        self.assertTrue(stored.is_ok(), stored)
        SystemSetting.objects.filter(key=key).update(value="malformed")
        cache.clear()
        self.addCleanup(cache.clear)
        accepted: list[str] = []

        @secure_service_method(
            SecurityConfig(
                rate_limit_key="registration",
                rate_limit=1,
                rate_limit_setting_key=key,
                log_attempts=False,
                prevent_timing_attacks=False,
            )
        )
        def register(*, request_ip: str) -> str:
            accepted.append(request_ip)
            return "accepted"

        first = register(request_ip="203.0.113.42")
        self.assertEqual(first.unwrap(), "accepted")
        second = register(request_ip="203.0.113.42")
        self.assertTrue(second.is_err(), second)
        self.assertEqual(counters.peek("rate_limit:registration:203.0.113.42"), 2)
        self.assertEqual(accepted, ["203.0.113.42"])
