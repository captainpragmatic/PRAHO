"""Deployed static files get content-hashed names, and every path a template asks for exists.

Django 5.1 removed STATICFILES_STORAGE and 5.2 ignores it, so the manifest storage prod and staging
asked for was never used: files were collected under their plain names while every Caddyfile serves
/static/ as immutable for a year, so a returning visitor kept old CSS and JS after a deploy. Under
the manifest storage a {% static %} path that was not collected is a ValueError (a 500), so each
literal path in the templates must resolve, and no template hardcodes a /static/ URL.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.staticfiles import finders

from tests.settings.test_logging_configuration import _PROD_ENV

MANIFEST = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
PLAIN = "django.contrib.staticfiles.storage.StaticFilesStorage"
STATIC_TAG = re.compile(r"""\{%\s*static\s+["']([^"']+)["']""")
HARDCODED = re.compile(r"""(?:src|href)=["']/static/""")
TEMPLATE_DIRS = (Path(settings.BASE_DIR) / "templates", Path(settings.REPO_ROOT) / "shared" / "ui" / "templates")


def _settings_module(name: str) -> ModuleType:
    previous = sys.modules.pop(name, None)
    try:
        with (
            patch.dict(os.environ, _PROD_ENV),
            patch("config.settings.base.IPWARE_TRUSTED_PROXY_LIST", ["127.0.0.1/32"]),
        ):
            return importlib.import_module(name)
    finally:
        sys.modules.pop(name, None)
        if previous is not None:
            sys.modules[name] = previous


def _templates() -> list[Path]:
    return [template for directory in TEMPLATE_DIRS for template in directory.rglob("*.html")]


@pytest.mark.parametrize("name", ["config.settings.prod", "config.settings.staging"])
def test_deployed_settings_use_the_manifest_storage(name: str) -> None:
    storages = _settings_module(name).STORAGES
    assert storages["staticfiles"]["BACKEND"] == MANIFEST
    assert storages["default"]["BACKEND"] == "django.core.files.storage.FileSystemStorage"


@pytest.mark.parametrize("name", ["config.settings.base", "config.settings.dev"])
def test_local_settings_keep_plain_names(name: str) -> None:
    assert _settings_module(name).STORAGES["staticfiles"]["BACKEND"] == PLAIN


def test_no_settings_module_uses_the_removed_setting() -> None:
    for module in (Path(settings.BASE_DIR) / "config" / "settings").glob("*.py"):
        assert "STATICFILES_STORAGE" not in module.read_text(), module.name


def test_every_static_path_in_the_templates_exists() -> None:
    paths = {match for template in _templates() for match in STATIC_TAG.findall(template.read_text())}
    assert paths
    missing = sorted(path for path in paths if finders.find(path) is None)
    assert missing == []


def test_no_template_hardcodes_a_static_url() -> None:
    # A literal /static/ URL bypasses the manifest and is cached under its plain name for a year.
    offenders = sorted(str(t.relative_to(settings.REPO_ROOT)) for t in _templates() if HARDCODED.search(t.read_text()))
    assert offenders == []
