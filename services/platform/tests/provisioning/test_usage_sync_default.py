"""Measured hosting usage is on unless an operator turns it off."""

from django.test import TestCase

from apps.provisioning import virtualmin_usage_service as usage
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class UsageSyncDefaultTests(TestCase):
    def test_usage_sync_is_enabled_when_no_operator_has_set_it(self) -> None:
        self.assertFalse(SystemSetting.objects.filter(key="provisioning.usage_sync_enabled").exists())

        self.assertTrue(usage.enabled())

    def test_the_catalog_default_matches_the_reader(self) -> None:
        self.assertIs(CATALOG_BY_KEY["provisioning.usage_sync_enabled"].default, True)

    def test_an_operator_can_still_turn_it_off(self) -> None:
        self.assertTrue(SettingsService.update_setting("provisioning.usage_sync_enabled", False).is_ok())

        self.assertFalse(usage.enabled())
