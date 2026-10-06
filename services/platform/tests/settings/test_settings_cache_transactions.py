"""Settings reads respect transaction visibility without publishing uncommitted values."""

from __future__ import annotations

from unittest.mock import patch

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

    def test_committed_update_during_miss_does_not_publish_stale_value(self) -> None:
        self._create(45)
        manager = SystemSetting.objects
        original_get = manager.get

        def read_then_commit(*, key: str) -> SystemSetting:
            old_row = original_get(key=key)
            with transaction.atomic():
                writer = original_get(key=key)
                writer.value = 60
                writer.save(update_fields=["value", "updated_at"])
            return old_row

        with patch.object(manager, "get", side_effect=read_then_commit):
            self.assertEqual(SettingsService.get_setting(self.key), 45)

        self.assertIsNone(self._cache_value())
        self.assertEqual(SettingsService.get_setting(self.key), 60)
        self.assertEqual(self._cache_value(), 60)

    def test_committed_create_during_miss_does_not_publish_stale_fallback(self) -> None:
        manager = SystemSetting.objects
        original_get = manager.get

        def miss_then_commit(*, key: str) -> SystemSetting:
            try:
                return original_get(key=key)
            except SystemSetting.DoesNotExist:
                with transaction.atomic():
                    self._create(60)
                raise

        with patch.object(manager, "get", side_effect=miss_then_commit):
            self.assertEqual(SettingsService.get_setting(self.key), 30)

        self.assertIsNone(self._cache_value())
        self.assertEqual(SettingsService.get_setting(self.key), 60)
        self.assertEqual(self._cache_value(), 60)

    def test_cache_hits_only_read_the_value_key(self) -> None:
        self._create(45)
        self.assertEqual(SettingsService.get_setting(self.key), 45)

        with patch("apps.settings.services.cache", wraps=cache) as observed_cache, self.assertNumQueries(0):
            self.assertEqual(SettingsService.get_setting(self.key), 45)

        observed_cache.get.assert_called_once()
        self.assertEqual(observed_cache.get.call_args.args[0], SettingsService._get_cache_key(self.key))
        self.assertEqual(observed_cache.get.call_args.kwargs, {"version": SettingsService.CACHE_VERSION})
        observed_cache.set.assert_not_called()
        observed_cache.delete.assert_not_called()

    def test_invalidation_rotates_nonexpiring_token_before_deleting_value(self) -> None:
        token_key = f"{SettingsService.CACHE_PREFIX}_token:{self.key}"
        value_key = SettingsService._get_cache_key(self.key)
        token_before: object = None
        original_delete = cache.delete

        def check_token_then_delete(key: str, *, version: int) -> bool:
            token_after = cache.get(token_key, version=version)
            self.assertIsInstance(token_after, str)
            self.assertNotEqual(token_after, token_before)
            return original_delete(key, version=version)

        for value in (45, 60):
            with self.subTest(value=value):
                cache.set(value_key, value, version=SettingsService.CACHE_VERSION)
                with (
                    patch("apps.settings.services.cache.delete", side_effect=check_token_then_delete),
                    patch("apps.settings.services.cache.set", wraps=cache.set) as observed_set,
                ):
                    SettingsService._clear_setting_cache(self.key)

                observed_set.assert_called_once_with(
                    token_key,
                    cache.get(token_key, version=SettingsService.CACHE_VERSION),
                    timeout=None,
                    version=SettingsService.CACHE_VERSION,
                )
                token_before = cache.get(token_key, version=SettingsService.CACHE_VERSION)
                self.assertIsNone(self._cache_value())

    def test_clear_all_cache_rotates_tokens_for_rows_and_rowless_defaults(self) -> None:
        rowless_key = "billing.invoice_payment_terms_days"
        self._create(45)
        self.assertFalse(SystemSetting.objects.filter(key=rowless_key).exists())
        self.assertEqual(SettingsService.get_setting(self.key), 45)
        self.assertEqual(SettingsService.get_setting(rowless_key), SettingsService.DEFAULT_SETTINGS[rowless_key])
        original_delete = cache.delete
        tokens_before = {
            key: cache.get(f"{SettingsService.CACHE_PREFIX}_token:{key}", version=SettingsService.CACHE_VERSION)
            for key in (self.key, rowless_key)
        }

        def check_token_then_delete(key: str, *, version: int) -> bool:
            for setting_key, token_before in tokens_before.items():
                if key == SettingsService._get_cache_key(setting_key):
                    token_after = cache.get(f"{SettingsService.CACHE_PREFIX}_token:{setting_key}", version=version)
                    self.assertIsInstance(token_after, str)
                    self.assertNotEqual(token_after, token_before)
            return original_delete(key, version=version)

        with patch("apps.settings.services.cache.delete", side_effect=check_token_then_delete):
            SettingsService.clear_all_cache()

        for key, token_before in tokens_before.items():
            with self.subTest(key=key):
                token_after = cache.get(
                    f"{SettingsService.CACHE_PREFIX}_token:{key}", version=SettingsService.CACHE_VERSION
                )
                self.assertIsInstance(token_after, str)
                self.assertNotEqual(token_after, token_before)
                self.assertIsNone(cache.get(SettingsService._get_cache_key(key), version=SettingsService.CACHE_VERSION))
