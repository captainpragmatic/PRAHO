"""The seed migrations create their rows on an empty database, and only once.

billing 0004 seeds the supported currencies and settings 0002 seeds the
selling-currency policy row. Each test empties the table first and calls the
seed function directly: a TransactionTestCase flush elsewhere in the suite
can remove migration-time rows, so reading them back would be order-dependent.
"""

from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

from django.apps import apps as global_apps
from django.db import connection
from django.test import TestCase

from apps.billing.models import Currency
from apps.settings.models import SystemSetting

# Migration module names start with a digit, so import them by string.
_currency_seed = import_module("apps.billing.migrations.0004_seed_supported_currencies")
_selling_currency_seed = import_module("apps.settings.migrations.0002_seed_selling_currency")


class MigrationSeedTests(TestCase):
    def test_currency_seed_creates_the_supported_currencies_once(self) -> None:
        Currency.objects.all().delete()

        _currency_seed.seed_currencies(global_apps, None)
        _currency_seed.seed_currencies(global_apps, None)

        self.assertEqual(
            set(Currency.objects.values_list("code", "symbol", "decimals", "name")),
            {
                ("RON", "lei", 2, "Romanian Leu"),
                ("EUR", "€", 2, "Euro"),
                ("USD", "$", 2, "US Dollar"),
            },
        )
        self.assertEqual(Currency.objects.count(), 3)

    def test_selling_currency_seed_creates_the_policy_row_once(self) -> None:
        SystemSetting.objects.all().delete()
        schema_editor = SimpleNamespace(connection=connection)

        _selling_currency_seed.seed_selling_currency(global_apps, schema_editor)
        _selling_currency_seed.seed_selling_currency(global_apps, schema_editor)

        self.assertEqual(SystemSetting.objects.count(), 1)
        setting = SystemSetting.objects.get(key="billing.default_currency")
        self.assertEqual(setting.value, "RON")
        self.assertEqual(setting.default_value, "RON")
        self.assertEqual(setting.revision, 1)
        self.assertEqual(setting.category, "billing")
        self.assertEqual(setting.data_type, "string")
