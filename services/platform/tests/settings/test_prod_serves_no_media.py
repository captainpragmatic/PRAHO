"""Production serves no media file directly.

Media holds invoices, fiscal records, attachments and exports. Each is read only through a Django
view that checks who is asking and records it. The edge has no /media/ route (tests/deploy), the
production URLconf has none, and no middleware treats /media/ as an open path.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

from django.test import SimpleTestCase, override_settings
from django.urls import Resolver404, resolve

from apps.common.localisation_middleware import LocalisationMiddleware
from apps.common.middleware import MaintenanceModeMiddleware, StaffMFAEnrollmentMiddleware
from tests.settings.test_media_storage import _settings_module


def _fresh_urlconf() -> ModuleType:
    previous = sys.modules.pop("config.urls", None)
    try:
        return importlib.import_module("config.urls")
    finally:
        sys.modules.pop("config.urls", None)
        if previous is not None:
            sys.modules["config.urls"] = previous


class ProductionServesNoMediaTests(SimpleTestCase):
    def test_production_settings_route_no_media_url(self) -> None:
        prod = _settings_module("config.settings.prod", {})
        path = f"{prod.MEDIA_URL}tickets/attachments/evidence.txt"
        self.assertFalse(prod.DEBUG)

        with (
            override_settings(DEBUG=prod.DEBUG, MEDIA_URL=prod.MEDIA_URL, MEDIA_ROOT=prod.MEDIA_ROOT),
            self.assertRaises(Resolver404),
        ):
            resolve(path, urlconf=_fresh_urlconf())
        # The check can tell: the development server does route media.
        with override_settings(DEBUG=True, MEDIA_URL=prod.MEDIA_URL, MEDIA_ROOT=prod.MEDIA_ROOT):
            self.assertEqual(resolve(path, urlconf=_fresh_urlconf()).func.__name__, "serve")

    def test_no_middleware_keeps_a_media_exemption(self) -> None:
        self.assertNotIn("/media/", StaffMFAEnrollmentMiddleware._OPEN_PREFIXES)
        self.assertNotIn("/media/", MaintenanceModeMiddleware.EXEMPT_PREFIXES)
        source = importlib.import_module(LocalisationMiddleware.__module__).__file__
        assert source is not None
        with open(source, encoding="utf-8") as handle:
            self.assertNotIn('"/media/"', handle.read())
