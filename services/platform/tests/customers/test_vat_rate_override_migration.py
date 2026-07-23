"""Migration coverage for explicit customer VAT-rate overrides."""

from __future__ import annotations

from decimal import Decimal

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

MIGRATE_FROM = ("customers", "0019_bind_payment_method_encryption_context")
MIGRATE_TO = ("customers", "0020_make_vat_rate_override_optional")


class VATRateOverrideMigrationTest(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
        customer_model = old_apps.get_model("customers", "Customer")
        tax_profile_model = old_apps.get_model("customers", "CustomerTaxProfile")

        self.profile_ids: dict[str, object] = {}
        for index, (label, is_vat_payer, vat_rate) in enumerate(
            (
                ("ambiguous_standard", True, Decimal("21.00")),
                ("generated_nonpayer", False, Decimal("0.00")),
                ("explicit_zero", True, Decimal("0.00")),
                ("explicit_reduced", True, Decimal("19.00")),
            )
        ):
            customer = customer_model.objects.create(
                name=f"Migration customer {index}",
                customer_type="company",
                status="active",
                primary_email=f"vat-migration-{index}@example.test",
            )
            profile = tax_profile_model.objects.create(
                customer=customer,
                is_vat_payer=is_vat_payer,
                vat_rate=vat_rate,
            )
            self.profile_ids[label] = profile.pk

    def tearDown(self) -> None:
        MigrationExecutor(connection).migrate([MIGRATE_TO])
        super().tearDown()

    def test_only_proven_generated_defaults_are_cleared(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_TO])
        migrated_apps = executor.loader.project_state([MIGRATE_TO]).apps
        tax_profile_model = migrated_apps.get_model("customers", "CustomerTaxProfile")

        rates = {
            label: tax_profile_model.objects.get(pk=profile_id).vat_rate
            for label, profile_id in self.profile_ids.items()
        }

        self.assertEqual(rates["ambiguous_standard"], Decimal("21.00"))
        self.assertIsNone(rates["generated_nonpayer"])
        self.assertEqual(rates["explicit_zero"], Decimal("0.00"))
        self.assertEqual(rates["explicit_reduced"], Decimal("19.00"))

    def test_reverse_migration_restores_non_null_legacy_defaults(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_TO])
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
        tax_profile_model = old_apps.get_model("customers", "CustomerTaxProfile")

        rates = {
            label: tax_profile_model.objects.get(pk=profile_id).vat_rate
            for label, profile_id in self.profile_ids.items()
        }

        self.assertEqual(rates["ambiguous_standard"], Decimal("21.00"))
        self.assertEqual(rates["generated_nonpayer"], Decimal("0.00"))
        self.assertEqual(rates["explicit_zero"], Decimal("0.00"))
        self.assertEqual(rates["explicit_reduced"], Decimal("19.00"))
