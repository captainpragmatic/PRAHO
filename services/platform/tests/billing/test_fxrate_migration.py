"""Migration coverage for provenanced FX rates."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

MIGRATE_FROM = ("billing", "0037_refund_gateway_id_unique")
MIGRATION_UNDER_TEST = ("billing", "0038_fxrate_provenance_and_constraints")
MIGRATE_TO = ("billing", "0039_invoice_tax_point_and_fx_snapshot")


class FXRateProvenanceMigrationTest(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
        currency_model = old_apps.get_model("billing", "Currency")
        fx_rate_model = old_apps.get_model("billing", "FXRate")
        eur, _ = currency_model.objects.get_or_create(
            code="EUR", defaults={"name": "Euro", "symbol": "EUR", "decimals": 2}
        )
        ron, _ = currency_model.objects.get_or_create(
            code="RON", defaults={"name": "Romanian leu", "symbol": "lei", "decimals": 2}
        )
        self.rate_id = fx_rate_model.objects.create(
            base_code=eur,
            quote_code=ron,
            rate=Decimal("5.01230000"),
            as_of=date(2026, 7, 17),
        ).pk

    def tearDown(self) -> None:
        MigrationExecutor(connection).migrate([MIGRATE_TO])
        super().tearDown()

    def test_existing_rate_keeps_value_without_invented_provenance(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATION_UNDER_TEST])
        migrated_apps = executor.loader.project_state([MIGRATION_UNDER_TEST]).apps
        fx_rate_model = migrated_apps.get_model("billing", "FXRate")

        migrated = fx_rate_model.objects.get(pk=self.rate_id)

        self.assertEqual(migrated.rate, Decimal("5.01230000"))
        self.assertEqual(migrated.source, "legacy_unknown")
        self.assertEqual(migrated.source_reference, "")
        self.assertIsNone(migrated.fetched_at)

    def test_invalid_historical_rate_blocks_constraint_migration(self) -> None:
        old_apps = MigrationExecutor(connection).loader.project_state([MIGRATE_FROM]).apps
        fx_rate_model = old_apps.get_model("billing", "FXRate")
        fx_rate_model.objects.filter(pk=self.rate_id).update(rate=Decimal("0"))

        try:
            with self.assertRaisesRegex(RuntimeError, "Cannot enforce positive FX rates"):
                MigrationExecutor(connection).migrate([MIGRATION_UNDER_TEST])
        finally:
            # Restore the pre-migration row so tearDown can return the shared schema to MIGRATE_TO.
            fx_rate_model.objects.filter(pk=self.rate_id).update(rate=Decimal("5.01230000"))
