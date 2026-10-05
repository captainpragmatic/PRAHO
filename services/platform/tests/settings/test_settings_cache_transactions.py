"""Settings reads respect transaction visibility without publishing uncommitted values."""

from __future__ import annotations

from django.core.cache import cache
from django.db import transaction
from django.test import TransactionTestCase, override_settings

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class SettingsCacheTransactionTests(TransactionTestCase):
    key = "billing.proforma_validity_days"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def _create(self, value: int) -> SystemSetting:
        return SystemSetting.objects.create(
            key=self.key,
            name="Proforma validity",
            description="Transaction visibility regression",
            category="billing",
            data_type="integer",
            value=value,
            default_value=30,
        )

    def _cache_value(self) -> object:
        return cache.get(SettingsService._get_cache_key(self.key), version=SettingsService.CACHE_VERSION)

    def test_warm_fallback_tracks_create_service_update_and_delete_inside_transaction(self) -> None:
        self.assertEqual(SettingsService.get_setting(self.key), 30)
        with transaction.atomic():
            setting = self._create(45)
            self.assertEqual(SettingsService.get_setting(self.key), 45)
            result = SettingsService.update_setting(self.key, 60)
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(SettingsService.get_setting(self.key), 60)
            setting.delete()
            self.assertEqual(SettingsService.get_setting(self.key), 30)
            self.assertEqual(self._cache_value(), 30)

        self.assertIsNone(self._cache_value())
        self.assertEqual(SettingsService.get_setting(self.key), 30)
        with self.assertNumQueries(0):
            self.assertEqual(SettingsService.get_setting(self.key), 30)

    def test_rollback_preserves_warm_committed_cache_across_nested_savepoint(self) -> None:
        setting = self._create(45)
        self.assertEqual(SettingsService.get_setting(self.key), 45)
        with transaction.atomic():
            with self.assertRaisesMessage(RuntimeError, "rollback"), transaction.atomic():
                setting.value = 60
                setting.save(update_fields=["value", "updated_at"])
                self.assertEqual(SettingsService.get_setting(self.key), 60)
                self.assertEqual(self._cache_value(), 45)
                raise RuntimeError("rollback")
            self.assertEqual(SettingsService.get_setting(self.key), 45)

        with self.assertNumQueries(0):
            self.assertEqual(SettingsService.get_setting(self.key), 45)

    def test_cold_transaction_read_is_not_published_before_rollback(self) -> None:
        self._create(45)
        with self.assertRaisesMessage(RuntimeError, "rollback"), transaction.atomic():
            result = SettingsService.update_setting(self.key, 60)
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(SettingsService.get_setting(self.key), 60)
            self.assertIsNone(self._cache_value())
            raise RuntimeError("rollback")

        self.assertEqual(SettingsService.get_setting(self.key), 45)

    def test_cache_refresh_clears_catalog_fallback_without_database_row(self) -> None:
        self.assertEqual(SettingsService.get_setting(self.key), 30)
        self.assertEqual(self._cache_value(), 30)
        self.assertFalse(SystemSetting.objects.filter(key=self.key).exists())

        SettingsService.clear_all_cache()

        self.assertIsNone(self._cache_value())
