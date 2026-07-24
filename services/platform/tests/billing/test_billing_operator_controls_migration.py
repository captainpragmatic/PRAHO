"""Migration coverage for billing operator-control state."""

from __future__ import annotations

from datetime import timedelta

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

MIGRATE_FROM = ("billing", "0042_vatvalidation_consultation_reference")
MIGRATE_TO = ("billing", "0043_billing_operator_controls")


class PaymentFailureTimestampMigrationTest(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
        customer_model = old_apps.get_model("customers", "Customer")
        currency_model = old_apps.get_model("billing", "Currency")
        payment_model = old_apps.get_model("billing", "Payment")
        customer = customer_model.objects.create(
            customer_type="company",
            company_name="Historical Failure SRL",
            name="Historical Failure SRL",
            status="active",
        )
        currency, _ = currency_model.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        failed_payment = payment_model.objects.create(
            customer=customer,
            currency=currency,
            amount_cents=10_000,
            status="failed",
        )
        self.historical_failure_at = timezone.now() - timedelta(days=2)
        payment_model.objects.filter(pk=failed_payment.pk).update(updated_at=self.historical_failure_at)
        self.failed_payment_id = failed_payment.pk
        self.pending_payment_id = payment_model.objects.create(
            customer=customer,
            currency=currency,
            amount_cents=10_000,
            status="pending",
        ).pk

    def tearDown(self) -> None:
        MigrationExecutor(connection).migrate([MIGRATE_TO])
        super().tearDown()

    def test_only_historical_failures_are_anchored_to_their_last_known_transition_time(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_TO])
        migrated_apps = executor.loader.project_state([MIGRATE_TO]).apps
        payment_model = migrated_apps.get_model("billing", "Payment")

        failed_payment = payment_model.objects.get(pk=self.failed_payment_id)
        pending_payment = payment_model.objects.get(pk=self.pending_payment_id)

        self.assertEqual(failed_payment.failed_at, self.historical_failure_at)
        self.assertIsNone(pending_payment.failed_at)
