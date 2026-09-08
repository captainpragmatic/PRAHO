"""Development deployment DNS zone seeding contracts."""

from io import StringIO
from unittest import mock

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.common.management.commands.generate_sample_data import Command
from apps.common.types import Err
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService, SettingValidationError

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

    def test_handle_invokes_seed_and_reports_write_failure_on_stderr(self) -> None:
        """handle() must run the seed, and a write failure must reach stderr (the
        Makefile wraps this command in `|| echo`, so exit-0 stdout noise is invisible)."""
        stderr = StringIO()
        failure = Err(SettingValidationError(key=DNS_ZONE_KEY, field="system", message="boom", code="system_error"))
        with (
            override_settings(DEBUG=True),
            mock.patch.object(Command, "_generate"),
            mock.patch.object(SettingsService, "update_setting", return_value=failure) as update,
        ):
            call_command("generate_sample_data", stdout=StringIO(), stderr=stderr)
        update.assert_called_once()
        self.assertIn("Deployment DNS zone seed failed", stderr.getvalue())

    def test_preserved_zone_failing_deployment_validation_warns_on_stderr(self) -> None:
        stderr = StringIO()
        with self.captureOnCommitCallbacks(execute=True):
            SystemSetting.objects.create(
                key=DNS_ZONE_KEY, value=" spacey.example.com ", default_value="", data_type="string"
            )
        cache.clear()

        command = Command(stdout=StringIO(), stderr=stderr)
        with self.captureOnCommitCallbacks(execute=True):
            command._seed_deployment_dns_zone()

        self.assertIn("fails deployment", stderr.getvalue())
        self.assertEqual(SystemSetting.objects.get(key=DNS_ZONE_KEY).value, " spacey.example.com ")
