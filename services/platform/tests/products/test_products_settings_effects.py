"""Product size and price guards use configured limits without reads inside loops."""

from contextlib import nullcontext
from typing import ClassVar

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.products.models import Product, ProductPrice, validate_custom_period_prices, validate_json_field
from apps.settings.services import SettingsService


class ProductSettingsEffectsTests(TestCase):
    def test_max_json_content_size_governs_both_size_guards(self) -> None:
        result = SettingsService.update_setting("products.max_json_content_size", 10)
        self.assertTrue(result.is_ok(), result)
        with self.assertRaisesMessage(ValidationError, "JSON content too large"):
            validate_json_field({"safe": "x" * 11})
        product = Product(slug="limit", name="Limit", tags=["x" * 7])
        with self.assertRaisesMessage(ValidationError, "tags too large"):
            product.clean()
        for size in (9, 10):
            validate_json_field({"safe": "x" * size})
            validate_json_field(["x" * (size - 4)], "tags")
        # General nested structures retain their existing relaxed size policy.
        validate_json_field({"first": "x" * 11, "second": "x" * 11})
        result = SettingsService.update_setting("products.max_json_content_size", 100)
        self.assertTrue(result.is_ok(), result)
        validate_json_field({"safe": "x" * 11})
        product.clean()
        with self.assertRaisesMessage(ValidationError, "Dangerous key 'exec'"):
            validate_json_field({"exec": "safe"})

    def test_max_price_cents_governs_custom_and_monthly_prices(self) -> None:
        result = SettingsService.update_setting("products.max_price_cents", 1000)
        self.assertTrue(result.is_ok(), result)
        with self.assertRaisesMessage(ValidationError, "Custom prices require"):
            validate_custom_period_prices({"30": 1001})
        price = ProductPrice(monthly_price_cents=1001)
        with self.assertRaisesMessage(ValidationError, "Monthly price too large"):
            price.clean()
        for amount in (999, 1000):
            validate_custom_period_prices({"30": amount})
            ProductPrice(monthly_price_cents=amount).clean()
        result = SettingsService.update_setting("products.max_price_cents", 1002)
        self.assertTrue(result.is_ok(), result)
        validate_custom_period_prices({"30": 1001})
        price.clean()
        with self.assertRaisesMessage(ValidationError, "Custom prices require"):
            validate_custom_period_prices({"30": True})
        with self.assertRaisesMessage(ValidationError, "Monthly price cannot be negative"):
            ProductPrice(monthly_price_cents=-1).clean()


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "product-limits"}}
)
class ProductSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def check_queries(self, *, atomic: bool) -> None:
        with transaction.atomic() if atomic else nullcontext():
            try:
                self.assertEqual(connection.get_autocommit(), not atomic)
                for key, value in (("products.max_json_content_size", 10), ("products.max_price_cents", 1000)):
                    if atomic:
                        result = SettingsService.update_setting(key, value)
                        self.assertTrue(result.is_ok(), result)
                    else:
                        cache.set(SettingsService._get_cache_key(key), value, version=SettingsService.CACHE_VERSION)
                for size in (1, 25):
                    prices = {str(day): 1000 for day in range(1, size + 1)}
                    prices[str(size)] = 1001
                    with self.subTest(path="custom prices", size=size):
                        with (
                            CaptureQueriesContext(connection) as queries,
                            self.assertRaisesMessage(ValidationError, "Custom prices require"),
                        ):
                            validate_custom_period_prices(prices)
                        self.assertEqual(len(queries), int(atomic))
                    with self.subTest(path="model JSON", size=size):
                        with (
                            CaptureQueriesContext(connection) as queries,
                            self.assertRaisesMessage(ValidationError, "meta too large"),
                        ):
                            validate_json_field({"safe": ["x"] * size}, "meta")
                        self.assertEqual(len(queries), int(atomic))
                with self.subTest(path="single JSON value"):
                    with (
                        CaptureQueriesContext(connection) as queries,
                        self.assertRaisesMessage(ValidationError, "JSON content too large"),
                    ):
                        validate_json_field({"safe": "x" * 11}, "meta")
                    self.assertEqual(len(queries), int(atomic))
                with self.subTest(path="monthly price"):
                    with (
                        CaptureQueriesContext(connection) as queries,
                        self.assertRaisesMessage(ValidationError, "Monthly price too large"),
                    ):
                        ProductPrice(monthly_price_cents=1001).clean()
                    self.assertEqual(len(queries), int(atomic))
            finally:
                if atomic:
                    transaction.set_rollback(True)

    def test_warm_cache_enforces_limits_without_queries(self) -> None:
        self.check_queries(atomic=False)

    def test_atomic_validation_reads_once_outside_loops(self) -> None:
        self.check_queries(atomic=True)
