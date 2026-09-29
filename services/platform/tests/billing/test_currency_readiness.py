"""Readiness checks use the stored policy and remain safe before schema upgrades."""

from decimal import Decimal
from io import StringIO
from unittest.mock import patch

from django.core.cache import cache
from django.core.checks import run_checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import OperationalError, connection, transaction
from django.db.models import JSONField, Value
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, FXRate
from apps.common.types import Ok
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class SellingCurrencyReadinessTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("5"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="readiness-test", fetched_at=timezone.now(),
                )
        get_selling_currency_policy(lock=True)

    @staticmethod
    def readiness(**overrides):
        return run_checks(tags=["billing_currency"], databases=overrides.get("databases", ["default"]))

    def test_stored_foreign_currency_requires_fx_even_when_environment_says_ron(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        FXRate.objects.filter(base_code_id="EUR").delete()
        with override_settings(BILLING_DEFAULT_CURRENCY="RON"):
            errors = self.readiness()
        self.assertEqual([error.id for error in errors], ["billing.E001"])
        self.assertIn("EUR", errors[0].msg)
        self.assertIn("billing.default_currency", errors[0].msg)

    def test_provenanced_stored_currency_ignores_a_conflicting_or_invalid_environment(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        for value in ("EUR", "XXX", None, 123):
            with self.subTest(environment=value), override_settings(BILLING_DEFAULT_CURRENCY=value):
                self.assertEqual(self.readiness(), [])

    def test_stored_ron_does_not_require_foreign_fx(self):
        FXRate.objects.all().delete()
        with override_settings(BILLING_DEFAULT_CURRENCY="EUR"):
            self.assertEqual(self.readiness(), [])

    def test_latest_unprovenanced_rate_blocks_readiness(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        FXRate.objects.filter(base_code_id="EUR").update(source=FXRate.Source.LEGACY_UNKNOWN)
        errors = self.readiness()
        self.assertEqual([error.id for error in errors], ["billing.E001"])
        self.assertIn("EUR", errors[0].msg)

    def test_unknown_stored_currency_is_reported_without_crashing(self):
        for value in ("XXX", "", None, 123):
            with self.subTest(value=value):
                SystemSetting.objects.filter(key="billing.default_currency").update(value=Value(value, output_field=JSONField()))
                errors = self.readiness()
                self.assertEqual([error.id for error in errors], ["billing.E001"])

    def test_ordinary_checks_and_unrelated_databases_do_not_query(self):
        for databases in (None, [], ["unrelated"]):
            with self.subTest(databases=databases), override_settings(BILLING_DEFAULT_CURRENCY="EUR"), self.assertNumQueries(0):
                self.assertEqual(self.readiness(databases=databases), [])

    def test_unreachable_database_is_an_error_when_readiness_was_requested(self):
        with patch.object(connection, "cursor", side_effect=OperationalError("database unavailable")):
            errors = self.readiness()
        self.assertEqual([error.id for error in errors], ["billing.E002"])

    def test_management_command_requires_database_flag_to_prove_readiness(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        FXRate.objects.filter(base_code_id="EUR").delete()
        call_command("check", "--tag", "billing_currency", stdout=StringIO())
        with self.assertRaisesMessage(SystemCheckError, "billing.E001"):
            call_command("check", "--tag", "billing_currency", "--database", "default", stdout=StringIO())

    def test_missing_policy_row_keeps_upgrade_ron_baseline_without_creating_data(self):
        SystemSetting.objects.filter(key="billing.default_currency").delete()
        FXRate.objects.all().delete()
        with override_settings(BILLING_DEFAULT_CURRENCY="EUR"):
            self.assertEqual(self.readiness(), [])
        self.assertFalse(SystemSetting.objects.filter(key="billing.default_currency").exists())

    def _check_legacy_schema(self, ddl):
        if connection.vendor != "postgresql":
            self.skipTest("Exercises reversible PostgreSQL schema changes")
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(ddl)
            try:
                with override_settings(BILLING_DEFAULT_CURRENCY="EUR"):
                    errors = self.readiness()
            finally:
                transaction.set_rollback(True)
        self.assertEqual(errors, [])
        self.assertEqual(get_selling_currency_policy().currency_code, "RON")

    def test_uninstalled_settings_table_allows_bootstrap(self):
        FXRate.objects.all().delete()
        self._check_legacy_schema('ALTER TABLE "setting_entries" RENAME TO "currency_check_legacy_entries"')

    def test_pre_revision_schema_allows_migrations(self):
        FXRate.objects.all().delete()
        self._check_legacy_schema('ALTER TABLE "setting_entries" RENAME COLUMN "revision" TO "currency_check_old_revision"')
