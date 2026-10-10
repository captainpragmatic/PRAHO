"""The login timing floor is on in production and cannot be configured into a no-op."""

import re
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from config.settings.base import login_floor_seconds

SETTINGS = Path(__file__).resolve().parents[2] / "config" / "settings"


class LoginFloorSettingTests(SimpleTestCase):
    def test_unset_or_empty_means_the_default(self) -> None:
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                self.assertEqual(login_floor_seconds(raw, 1.0), 1.0)

    def test_a_valid_override_is_used(self) -> None:
        for raw, value in (("1", 1.0), ("1.5", 1.5), ("10", 10.0)):
            with self.subTest(raw=raw):
                self.assertEqual(login_floor_seconds(raw, 1.0), value)

    def test_values_that_would_disable_or_break_the_floor_refuse_to_start(self) -> None:
        # Below the measured default hides too little (0.001 as much as 0); nan would turn the
        # protection off silently; inf would hang every login.
        for raw in ("abc", "0", "-1", "1e-9", "0.001", "0.5", "0.999", "nan", "inf", "-inf", "10.5", "1e9"):
            with self.subTest(raw=raw), self.assertRaises(ImproperlyConfigured):
                login_floor_seconds(raw, 1.0)

    def test_production_and_staging_turn_the_floor_on_at_one_second(self) -> None:
        for name in ("prod.py", "staging.py"):
            with self.subTest(settings=name):
                source = (SETTINGS / name).read_text(encoding="utf-8")
                self.assertRegex(
                    source,
                    # Anchored at a line start, so a commented-out assignment does not count.
                    re.compile(
                        r"^PLATFORM_API_AUTH_MIN_DURATION_SECONDS = login_floor_seconds\(\s*\n?\s*"
                        r'os\.environ\.get\("PLATFORM_API_AUTH_MIN_DURATION_SECONDS"\), 1\.0\s*\)',
                        re.MULTILINE,
                    ),
                )
