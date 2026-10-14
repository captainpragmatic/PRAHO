"""The customer portal's public origin follows the deployment's PORTAL_DOMAIN until staff set their own.

Production requires PORTAL_DOMAIN, yet the portal URL used for customer links was a separate setting
that started blank: on a fresh deployment, registration and password-reset mail and the legal-page
redirects failed until someone typed the same domain into Settings.
"""

from __future__ import annotations

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.services import portal_public_origin


class PortalOriginTests(TestCase):
    def setUp(self) -> None:
        SystemSetting.objects.filter(key="portal.public_base_url").delete()
        cache.clear()
        self.addCleanup(cache.clear)

    def set_origin(self, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("portal.public_base_url", value)
        self.assertTrue(result.is_ok(), result)

    @override_settings(PORTAL_DOMAIN="portal.operator.test")
    def test_the_origin_follows_portal_domain_until_staff_set_their_own(self) -> None:
        self.assertEqual(portal_public_origin(), "https://portal.operator.test")
        self.set_origin("")  # A row seeded blank before this release inherits too
        self.assertEqual(portal_public_origin(), "https://portal.operator.test")
        self.set_origin("https://customers.operator.test")
        self.assertEqual(portal_public_origin(), "https://customers.operator.test")

    @override_settings(PORTAL_DOMAIN="")
    def test_without_either_there_is_no_origin(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            portal_public_origin()
