"""Coupon generation snapshots the default retry budget at call time."""

from typing import ClassVar
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.promotions.models import Coupon
from apps.settings.services import SettingsService


class PromotionSettingsEffectsTests(TestCase):
    def test_max_code_generation_attempts_bounds_collisions_and_preserves_explicit_budget(self) -> None:
        Coupon.objects.create(code="A", name="Collision", discount_percent=10)
        result = SettingsService.update_setting("promotions.max_code_generation_attempts", 1)
        self.assertTrue(result.is_ok(), result)
        with (
            patch("apps.promotions.models.secrets.choice", side_effect=["A", "B"]),
            self.assertRaisesMessage(ValueError, "after 1 attempts"),
        ):
            Coupon.generate_code(length=1)
        with patch("apps.promotions.models.secrets.choice", side_effect=["A", "B"]):
            self.assertEqual(Coupon.generate_code(length=1, max_attempts=2), "B")
        result = SettingsService.update_setting("promotions.max_code_generation_attempts", 2)
        self.assertTrue(result.is_ok(), result)
        with patch("apps.promotions.models.secrets.choice", side_effect=["A", "B"]):
            self.assertEqual(Coupon.generate_code(length=1), "B")
        with self.assertRaisesMessage(ValueError, "after 0 attempts"):
            Coupon.generate_code(length=1, max_attempts=0)


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "coupon-attempts"}}
)
class PromotionSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_warm_cache_zero_budget_stops_before_uniqueness_query(self) -> None:
        self.assertTrue(connection.get_autocommit())
        key = "promotions.max_code_generation_attempts"
        cache.set(SettingsService._get_cache_key(key), 0, version=SettingsService.CACHE_VERSION)
        with (
            CaptureQueriesContext(connection) as queries,
            self.assertRaisesMessage(ValueError, "after 0 attempts"),
        ):
            Coupon.generate_code(length=1)
        self.assertEqual(len(queries), 0)
        cache.set(SettingsService._get_cache_key(key), 2, version=SettingsService.CACHE_VERSION)
        with (
            patch("apps.promotions.models.secrets.choice", return_value="B"),
            CaptureQueriesContext(connection) as queries,
        ):
            self.assertEqual(Coupon.generate_code(length=1), "B")
        self.assertEqual(len(queries), 1)

    def test_atomic_budget_is_read_once_before_collision_loop(self) -> None:
        with transaction.atomic():
            try:
                Coupon.objects.create(code="A", name="Collision", discount_percent=10)
                key = "promotions.max_code_generation_attempts"
                result = SettingsService.update_setting(key, 1)
                self.assertTrue(result.is_ok(), result)
                with (
                    patch("apps.promotions.models.secrets.choice", side_effect=["A", "B"]),
                    CaptureQueriesContext(connection) as queries,
                    self.assertRaisesMessage(ValueError, "after 1 attempts"),
                ):
                    Coupon.generate_code(length=1)
                self.assertEqual(len(queries), 2)
                for attempts in (2, 25):
                    result = SettingsService.update_setting(key, attempts)
                    self.assertTrue(result.is_ok(), result)
                    with (
                        patch("apps.promotions.models.secrets.choice", side_effect=["A"] * (attempts - 1) + ["B"]),
                        CaptureQueriesContext(connection) as queries,
                    ):
                        self.assertEqual(Coupon.generate_code(length=1), "B")
                    self.assertEqual(len(queries), attempts + 1)
                with (
                    patch("apps.promotions.models.secrets.choice", side_effect=["A", "B"]),
                    CaptureQueriesContext(connection) as queries,
                ):
                    self.assertEqual(Coupon.generate_code(length=1, max_attempts=2), "B")
                self.assertEqual(len(queries), 2)
            finally:
                transaction.set_rollback(True)
