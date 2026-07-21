"""Migration coverage for row-bound customer payment-method encryption."""

from __future__ import annotations

import json
import uuid
from importlib import import_module
from unittest.mock import patch

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

from apps.common.encryption import (
    VERSIONED_V2_PREFIX,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)
from apps.common.fields import _extract_embedded_aad

TEST_KEY = "iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs="
MIGRATE_FROM = ("customers", "0018_remove_dormant_auto_payment_flag")
MIGRATE_TO = ("customers", "0019_bind_payment_method_encryption_context")
DETAILS = {"bank_name": "BT", "iban": "RO49AAAA1B31007593840000"}


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class PaymentMethodEncryptionMigrationTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
        Customer = old_apps.get_model("customers", "Customer")
        payment_method_model = old_apps.get_model("customers", "CustomerPaymentMethod")
        customer = Customer.objects.create(
            name="Migration Customer",
            customer_type="company",
            status="active",
            primary_email="migration@example.test",
        )
        self.payment_method = payment_method_model.objects.create(
            customer=customer,
            method_type="bank_transfer",
            display_name="Legacy bank",
            bank_details=None,
        )
        # Reproduce the old auto-increment INSERT behavior: the pk was unavailable,
        # so the v2 AAD row component was empty.
        old_wire = encrypt_sensitive_data(
            json.dumps(DETAILS),
            aad=b"customer_payment_methods:bank_details:",
        )
        self.initial_raw = json.dumps(old_wire)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [self.initial_raw, self.payment_method.pk],
            )

    def tearDown(self) -> None:
        MigrationExecutor(connection).migrate([MIGRATE_TO])
        super().tearDown()

    def test_forward_and_reverse_preserve_data_and_bind_exact_context(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_TO])
        migrated_apps = executor.loader.project_state([MIGRATE_TO]).apps
        payment_method_model = migrated_apps.get_model(
            "customers",
            "CustomerPaymentMethod",
        )
        migrated = payment_method_model.objects.get(pk=self.payment_method.pk)

        self.assertEqual(migrated.bank_details, DETAILS)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT encryption_context_id, bank_details "
                "FROM customer_payment_methods WHERE id = %s",
                [self.payment_method.pk],
            )
            raw_context, raw_value = cursor.fetchone()
        context = uuid.UUID(str(raw_context))
        wire = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
        self.assertTrue(wire.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(
            _extract_embedded_aad(wire),
            f"customer_payment_methods:bank_details:{context}".encode(),
        )

        with self.assertRaises(DatabaseError), transaction.atomic():
            payment_method_model.objects.filter(pk=migrated.pk).update(
                encryption_context_id=uuid.uuid4()
            )

        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [self.payment_method.pk],
            )
            restored_raw = cursor.fetchone()[0]
        restored_wire = (
            json.loads(restored_raw)
            if isinstance(restored_raw, str)
            else restored_raw
        )
        expected_aad = (
            f"customer_payment_methods:bank_details:{self.payment_method.pk}".encode()
        )
        self.assertEqual(_extract_embedded_aad(restored_wire), expected_aad)
        self.assertEqual(
            json.loads(decrypt_sensitive_data(restored_wire, aad=expected_aad)),
            DETAILS,
        )

    def test_forward_migration_aborts_instead_of_overwriting_changed_ciphertext(self) -> None:
        migration = import_module(
            "apps.customers.migrations.0019_bind_payment_method_encryption_context"
        )
        stale_wire = encrypt_sensitive_data(
            json.dumps({"bank_name": "Stale"}),
            aad=b"customer_payment_methods:bank_details:",
        )
        stale_row = (
            self.payment_method.pk,
            None,
            json.dumps(stale_wire),
        )

        executor = MigrationExecutor(connection)
        with (
            patch.object(
                migration,
                "_rows",
                return_value=iter([stale_row]),
            ),
            self.assertRaises(RuntimeError),
        ):
            executor.migrate([MIGRATE_TO])

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [self.payment_method.pk],
            )
            unchanged = cursor.fetchone()[0]
        self.assertNotEqual(unchanged, stale_row[2])

    def test_forward_accepts_historical_primary_key_bound_v2(self) -> None:
        historical = encrypt_sensitive_data(
            json.dumps(DETAILS),
            aad=(
                f"customer_payment_methods:bank_details:{self.payment_method.pk}"
            ).encode(),
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [json.dumps(historical), self.payment_method.pk],
            )

        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_TO])
        migrated_apps = executor.loader.project_state([MIGRATE_TO]).apps
        payment_method_model = migrated_apps.get_model(
            "customers",
            "CustomerPaymentMethod",
        )

        self.assertEqual(
            payment_method_model.objects.get(pk=self.payment_method.pk).bank_details,
            DETAILS,
        )

    def test_forward_rejects_v2_bound_to_an_unexpected_context(self) -> None:
        unexpected = encrypt_sensitive_data(
            json.dumps(DETAILS),
            aad=b"customer_payment_methods:bank_details:another-row",
        )
        unexpected_raw = json.dumps(unexpected)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [unexpected_raw, self.payment_method.pk],
            )

        try:
            with self.assertRaises(RuntimeError):
                MigrationExecutor(connection).migrate([MIGRATE_TO])

            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                    [self.payment_method.pk],
                )
                unchanged = cursor.fetchone()[0]
            self.assertEqual(unchanged, unexpected_raw)
        finally:
            # Leave the pre-migration fixture valid so tearDown can restore the
            # schema even after this deliberately rejected migration.
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                    [self.initial_raw, self.payment_method.pk],
                )
