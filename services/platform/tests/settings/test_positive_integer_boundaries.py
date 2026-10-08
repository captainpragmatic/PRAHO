"""Positive operational settings reject zero and tolerate legacy invalid rows."""

from django.core.cache import cache
from django.test import TestCase

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.helpers.legacy_settings import store_legacy_integer

POSITIVE_DEFAULTS = {
    "billing.efactura_api_max_retries": 3,
    "customers.task_soft_time_limit": 300,
    "customers.task_time_limit": 600,
    "infrastructure.health_check_timeout_seconds": 10,
    "infrastructure.network_probe_timeout_seconds": 10,
    "orders.task_time_limit": 900,
    "provisioning.ssh_timeout": 30,
    "provisioning.sudo_command_timeout": 60,
    "provisioning.task_soft_time_limit": 600,
    "provisioning.task_time_limit": 900,
    "virtualmin.max_retries": 3,
}


class PositiveIntegerBoundaryTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_nonpositive_writes_are_rejected_without_creating_rows(self) -> None:
        for key in POSITIVE_DEFAULTS:
            SystemSetting.objects.filter(key=key).delete()
            for value in (-1, 0):
                with self.subTest(key=key, value=value):
                    result = SettingsService.update_setting(key, value)
                    self.assertTrue(result.is_err(), f"{key} must reject {value}")
                    self.assertFalse(SystemSetting.objects.filter(key=key).exists())
            for value in (1, 17):
                with self.subTest(key=key, value=value):
                    result = SettingsService.update_setting(key, value)
                    self.assertTrue(result.is_ok(), result)
                    self.assertEqual(SystemSetting.objects.get(key=key).get_typed_value(), value)

    def test_legacy_nonpositive_rows_use_defaults_and_warn_without_rewriting_rows(
        self,
    ) -> None:
        for key, default in POSITIVE_DEFAULTS.items():
            for value in (-1, 0):
                with self.subTest(key=key, value=value):
                    store_legacy_integer(key, value)
                    with self.assertLogs("apps.settings.services", level="WARNING") as warnings:
                        resolved = SettingsService.get_integer_setting(key)
                        self.assertEqual(resolved, default)
                    self.assertTrue(any(key in message and "non-positive" in message for message in warnings.output))
                    self.assertEqual(SystemSetting.objects.get(key=key).value, str(value))
            store_legacy_integer(key, 1)
            self.assertEqual(SettingsService.get_integer_setting(key), 1)
            store_legacy_integer(key, 17)
            self.assertEqual(SettingsService.get_integer_setting(key), 17)
