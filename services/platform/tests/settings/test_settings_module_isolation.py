"""Importing one settings module never changes another's.

`from .base import *` binds base's own lists. Development settings that appended to them in place
(`MIDDLEWARE.insert`, `INSTALLED_APPS +=`) changed base for every later reader in the process, so a
test that imported dev settings leaked the debug toolbar into another test's copy of base.
"""

from __future__ import annotations

import importlib

from django.test import SimpleTestCase

from tests.settings.test_media_storage import _settings_module


class SettingsModuleIsolationTests(SimpleTestCase):
    def test_importing_dev_or_e2e_settings_leaves_base_lists_untouched(self) -> None:
        base = importlib.import_module("config.settings.base")
        before = {name: list(getattr(base, name)) for name in ("MIDDLEWARE", "INSTALLED_APPS")}
        for name in ("config.settings.dev", "config.settings.e2e"):
            with self.subTest(settings=name):
                _settings_module(name, {})
                self.assertEqual({key: list(getattr(base, key)) for key in before}, before)
