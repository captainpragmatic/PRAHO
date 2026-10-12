"""Deployed static files get content-hashed names, and every path a template asks for exists.

Django 5.1 removed STATICFILES_STORAGE and 5.2 ignores it, so the manifest storage the settings
asked for was never used: files were collected under their plain names while every Caddyfile serves
/static/ as immutable for a year, so a returning visitor kept old CSS and JS after a deploy. Under
the manifest storage a {% static %} path that was not collected is a ValueError (a 500), so each
literal path in the templates must resolve.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from django.conf import settings
from django.contrib.staticfiles import finders
from django.test import SimpleTestCase

from tests.settings.test_logging_configuration import _PROD_ENV

MANIFEST = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
PLAIN = "django.contrib.staticfiles.storage.StaticFilesStorage"
STATIC_TAG = re.compile(r"""\{%\s*static\s+["']([^"']+)["']""")
TEMPLATE_DIRS = (Path(settings.BASE_DIR) / "templates", Path(settings.REPO_ROOT) / "shared" / "ui" / "templates")


def _settings_module(name: str) -> ModuleType:
    previous = sys.modules.pop(name, None)
    try:
        with patch.dict(os.environ, _PROD_ENV), patch("config.settings.base.validate_production_secret_key"):
            return importlib.import_module(name)
    finally:
        sys.modules.pop(name, None)
        if previous is not None:
            sys.modules[name] = previous


class StaticStorageTests(SimpleTestCase):
    def test_deployed_settings_use_the_manifest_storage(self) -> None:
        for name in ("config.settings.prod", "config.settings.staging"):
            with self.subTest(settings=name):
                module = _settings_module(name)
                self.assertEqual(module.STORAGES["staticfiles"]["BACKEND"], MANIFEST)
                self.assertEqual(module.STORAGES["default"]["BACKEND"], "django.core.files.storage.FileSystemStorage")

    def test_local_settings_keep_plain_names(self) -> None:
        self.assertEqual(settings.STORAGES["staticfiles"]["BACKEND"], PLAIN)
        for name in ("config.settings.dev", "config.settings.base"):
            with self.subTest(settings=name):
                self.assertEqual(_settings_module(name).STORAGES["staticfiles"]["BACKEND"], PLAIN)

    def test_no_settings_module_uses_the_removed_setting(self) -> None:
        for module in sorted((Path(settings.BASE_DIR) / "config" / "settings").glob("*.py")):
            with self.subTest(module=module.name):
                self.assertNotIn("STATICFILES_STORAGE", module.read_text())

    def test_every_static_path_in_the_templates_exists(self) -> None:
        paths = {
            match
            for directory in TEMPLATE_DIRS
            for template in directory.rglob("*.html")
            for match in STATIC_TAG.findall(template.read_text())
        }
        self.assertTrue(paths)
        for path in sorted(paths):
            with self.subTest(path=path):
                self.assertIsNotNone(finders.find(path), path)
