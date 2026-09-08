"""Development deployment DNS zone seeding contracts."""

from io import StringIO

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.management.commands.generate_sample_data import Command
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

DNS_ZONE_KEY = "node_deployment.dns_default_zone"


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "sample-data-dns-zone-tests",
        }
    }
)
class SampleDataDNSZoneTests(TestCase):
    def setUp(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            SystemSetting.objects.filter(key=DNS_ZONE_KEY).delete()
        cache.clear()
        self.addCleanup(cache.clear)
        self.command = Command(stdout=StringIO())

    def _write_zone(self, value: str) -> SystemSetting:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(DNS_ZONE_KEY, value)
        self.assertTrue(result.is_ok(), str(result))
        return result.unwrap()

    def _seed_zone(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.command._seed_deployment_dns_zone()

    def test_seeds_missing_dns_zone(self) -> None:
        self.assertFalse(SystemSetting.objects.filter(key=DNS_ZONE_KEY).exists())
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY, ""), "")

        self._seed_zone()

        self.assertEqual(SystemSetting.objects.get(key=DNS_ZONE_KEY).value, "dev.praho.local")
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "dev.praho.local")

    def test_seeds_empty_dns_zone(self) -> None:
        setting = self._write_zone("")
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "")

        self._seed_zone()

        setting.refresh_from_db()
        self.assertEqual(setting.value, "dev.praho.local")
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "dev.praho.local")

    def test_preserves_configured_dns_zone(self) -> None:
        setting = self._write_zone("infra.example.com")
        original_updated_at = setting.updated_at

        self._seed_zone()

        setting.refresh_from_db()
        self.assertEqual(setting.value, "infra.example.com")
        self.assertEqual(setting.updated_at, original_updated_at)
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "infra.example.com")

    def test_dns_zone_seed_is_idempotent(self) -> None:
        self._seed_zone()
        setting = SystemSetting.objects.get(key=DNS_ZONE_KEY)
        self.assertEqual(setting.value, "dev.praho.local")
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "dev.praho.local")
        original_updated_at = setting.updated_at

        self._seed_zone()

        setting.refresh_from_db()
        self.assertEqual(setting.value, "dev.praho.local")
        self.assertEqual(setting.updated_at, original_updated_at)
        self.assertEqual(SettingsService.get_setting(DNS_ZONE_KEY), "dev.praho.local")
        self.assertEqual(SystemSetting.objects.filter(key=DNS_ZONE_KEY).count(), 1)
