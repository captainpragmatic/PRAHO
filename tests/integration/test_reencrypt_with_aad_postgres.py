"""PostgreSQL coverage for the ``reencrypt_with_aad`` v1→v2 AAD migration (#270 item 1).

The command reads and rewrites ``EncryptedJSONField`` columns with a converter-free
cursor and a compare-and-swap, deliberately bypassing the ORM (``from_db_value``
decrypts on read, so an "is it v2?" check via the ORM can never fire). That raw path
depends on backend-specific behavior that the unit suite cannot exercise:

  * reading a ``jsonb`` column returns the value as JSON **text**, not a parsed object
  * writing a Python ``str`` into a ``jsonb`` column coerces correctly
  * the CAS ``WHERE col = %s`` comparison works against ``jsonb``

``tests/common/test_reencrypt_with_aad.py`` covers the command's logic thoroughly but
runs on SQLite, where the column is plain ``TEXT`` — so none of the above is tested
there. The command's own docstring calls this out and mandates a manual ``--dry-run``
against a PostgreSQL copy before any production run. These tests close that gap in CI.

This module lives under ``tests/integration/`` because that is what the PostgreSQL job
runs (``make test-integration``); the platform suite runs on SQLite only.

``ReencryptRekeyPostgresTest`` extends the same guarantees to the ``--rekey`` branch
(#466): it reuses the write mechanism proven above, but nothing exercised that branch
on jsonb, and its readability proof bypassed the ORM.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase, override_settings

from apps.common.encryption import (
    VERSIONED_V2_PREFIX,
    _clear_aesgcm_cache,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)
from apps.common.fields import _extract_embedded_aad
from apps.customers.models import Customer, CustomerPaymentMethod

TEST_KEY = "iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs="
VALID = {"bank_name": "BT", "iban": "RO49AAAA1B31007593840000"}

pytestmark = pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason=f"PostgreSQL-specific jsonb behavior (current backend: {connection.vendor})",
)


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class ReencryptWithAadPostgresTest(TestCase):
    """Exercise the raw read/classify/CAS path against a real jsonb column."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Reencrypt PG Customer",
            customer_type="company",
            status="active",
            primary_email="reencrypt-pg@test.ro",
            primary_phone="+40712345684",
        )

    def _make_pm(self, display: str = "PG-PM") -> CustomerPaymentMethod:
        return CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name=display, bank_details=None
        )

    def _write_raw(self, pk: int, wire_or_value: object) -> None:
        """Write the physical column exactly as the ORM stores it (a JSON string)."""
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [json.dumps(wire_or_value), pk],
            )

    def _read_raw(self, pk: int) -> object:
        with connection.cursor() as cursor:
            cursor.execute("SELECT bank_details FROM customer_payment_methods WHERE id = %s", [pk])
            raw = cursor.fetchone()[0]
        return json.loads(raw) if isinstance(raw, str) else raw

    def _seed_v1(self, pk: int, value: dict | None = None) -> None:
        wire = encrypt_sensitive_data(json.dumps(value if value is not None else VALID))
        assert wire.startswith("aes:v1:")
        self._write_raw(pk, wire)

    def test_column_is_jsonb(self) -> None:
        """Guard the premise: if this stops being jsonb, the rest proves nothing."""
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = 'customer_payment_methods' AND column_name = 'bank_details'"
            )
            self.assertEqual(cursor.fetchone()[0], "jsonb")

    def test_v1_row_migrated_to_v2_with_aad_on_postgres(self) -> None:
        """The full round trip: jsonb text read → classify → CAS write → readable v2."""
        pm = self._make_pm()
        self._seed_v1(pm.id)

        call_command("reencrypt_with_aad", stdout=StringIO())

        stored = self._read_raw(pm.id)
        self.assertIsInstance(stored, str)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(
            _extract_embedded_aad(stored),
            f"customer_payment_methods:bank_details:{pm.encryption_context_id}".encode(),
        )
        self.assertEqual(json.loads(decrypt_sensitive_data(stored)), VALID)

    def test_migrated_row_reads_back_through_the_orm(self) -> None:
        """The CAS write must leave a value the field's from_db_value can decrypt.

        A str→jsonb coercion that double-encoded (or stored the string as a JSON
        scalar the loader hands back differently) would still "look" migrated in raw
        SQL but break every application read.
        """
        pm = self._make_pm()
        self._seed_v1(pm.id)

        call_command("reencrypt_with_aad", stdout=StringIO())

        self.assertEqual(CustomerPaymentMethod.objects.get(pk=pm.id).bank_details, VALID)

    def test_idempotent_second_run_is_a_noop_on_postgres(self) -> None:
        """Already-v2 rows must be recognized as v2 when read back out of jsonb."""
        pm = self._make_pm()
        self._seed_v1(pm.id)
        call_command("reencrypt_with_aad", stdout=StringIO())
        after_first = self._read_raw(pm.id)

        call_command("reencrypt_with_aad", stdout=StringIO())

        self.assertEqual(self._read_raw(pm.id), after_first)

    def test_dry_run_writes_nothing_on_postgres(self) -> None:
        pm = self._make_pm()
        self._seed_v1(pm.id)
        before = self._read_raw(pm.id)

        call_command("reencrypt_with_aad", "--dry-run", stdout=StringIO())

        self.assertEqual(self._read_raw(pm.id), before)

    def test_plaintext_row_migrated_to_v2_on_postgres(self) -> None:
        """A stored plaintext JSON object (not a string) exercises the other jsonb shape."""
        pm = self._make_pm()
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [json.dumps(VALID), pm.id],
            )

        call_command("reencrypt_with_aad", stdout=StringIO())

        stored = self._read_raw(pm.id)
        self.assertIsInstance(stored, str)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(json.loads(decrypt_sensitive_data(stored)), VALID)

    def test_corrupt_row_flagged_and_not_overwritten_on_postgres(self) -> None:
        """Fail-closed behavior must survive the backend change, not just the logic."""
        pm = self._make_pm()
        corrupt_wire = "aes:v1:!!!notbase64!!!"  # cannot decrypt
        self._write_raw(pm.id, corrupt_wire)

        with self.assertRaises(CommandError):
            call_command("reencrypt_with_aad", stdout=StringIO(), stderr=StringIO())

        self.assertEqual(self._read_raw(pm.id), corrupt_wire)  # untouched


OLD_KEY = TEST_KEY
NEW_KEY = "1qJJ-NUI8b2icS59TkGTNII5z7GUdNZGadhdqdCSW1w="


@override_settings(ENCRYPTION_KEY=OLD_KEY)
class ReencryptRekeyPostgresTest(TestCase):
    """#466: the ``--rekey`` branch against a real jsonb column, incl. ORM readback.

    The migrate-path tests above prove the raw read/classify/CAS pipeline jsonb-safe;
    ``--rekey`` (#455) reuses that write mechanism but ran only on SQLite, and its
    readability proof called ``decrypt_sensitive_data`` directly rather than reading
    through the ORM — the check that catches a str→jsonb coercion bug invisible to
    raw SQL. Seeding mirrors ``ReencryptRekeyModeTest._pm_encrypted_under_old_key``.
    """

    def setUp(self) -> None:
        _clear_aesgcm_cache()
        self.customer = Customer.objects.create(
            name="Rekey PG Customer",
            customer_type="company",
            status="active",
            primary_email="rekey-pg@test.ro",
            primary_phone="+40712345685",
        )

    def tearDown(self) -> None:
        # Cached AESGCM instances must never leak across settings contexts.
        _clear_aesgcm_cache()

    def _pm_encrypted_under_old_key(self) -> CustomerPaymentMethod:
        """Create a v2 row whose ciphertext is bound to OLD_KEY only."""
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name="PG-Rekey-PM", bank_details=None
        )
        aad = f"customer_payment_methods:bank_details:{pm.encryption_context_id}".encode()
        wire = encrypt_sensitive_data(json.dumps(VALID), aad=aad)
        assert wire.startswith(VERSIONED_V2_PREFIX)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [json.dumps(wire), pm.id],
            )
        return pm

    def _read_raw(self, pk: int) -> object:
        with connection.cursor() as cursor:
            cursor.execute("SELECT bank_details FROM customer_payment_methods WHERE id = %s", [pk])
            raw = cursor.fetchone()[0]
        return json.loads(raw) if isinstance(raw, str) else raw

    def test_rekey_reencrypts_stale_row_on_postgres_and_reads_back_via_orm(self) -> None:
        pm = self._pm_encrypted_under_old_key()
        before = self._read_raw(pm.id)
        aad = f"customer_payment_methods:bank_details:{pm.encryption_context_id}".encode()
        stdout = StringIO()

        with override_settings(ENCRYPTION_KEYS=[NEW_KEY, OLD_KEY]):
            _clear_aesgcm_cache()
            call_command("reencrypt_with_aad", "--rekey", stdout=stdout)
            stored = self._read_raw(pm.id)

            # The physical jsonb value is a JSON string carrying a v2 wire with
            # the SAME AAD binding — rekey changes the key, never the identity.
            self.assertIsInstance(stored, str)
            assert isinstance(stored, str)
            self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))
            self.assertNotEqual(stored, before)
            self.assertEqual(_extract_embedded_aad(stored), aad)
            # Delimiter-bounded: a bare "1 rekeyed" would also match "11 rekeyed".
            self.assertIn(", 1 rekeyed,", stdout.getvalue())

            # The check #455's direct-decrypt proof skipped: the row must read
            # back through the ORM (from_db_value), which a str→jsonb coercion
            # bug would break while raw SQL still "looks" rekeyed.
            self.assertEqual(CustomerPaymentMethod.objects.get(pk=pm.id).bank_details, VALID)

        # The retirement criterion: readable under the NEW key ALONE.
        with override_settings(ENCRYPTION_KEYS=[NEW_KEY]):
            _clear_aesgcm_cache()
            assert isinstance(stored, str)
            self.assertEqual(json.loads(decrypt_sensitive_data(stored, aad=aad)), VALID)

    def test_second_rekey_run_reports_zero_rekeyed_on_postgres(self) -> None:
        pm = self._pm_encrypted_under_old_key()

        with override_settings(ENCRYPTION_KEYS=[NEW_KEY, OLD_KEY]):
            _clear_aesgcm_cache()
            call_command("reencrypt_with_aad", "--rekey", stdout=StringIO())
            after_first = self._read_raw(pm.id)

            second = StringIO()
            call_command("reencrypt_with_aad", "--rekey", stdout=second)

            # Idempotence on jsonb: the second pass must recognize the row as
            # current-key v2 when read back out of jsonb, and rewrite nothing.
            self.assertIn(", 0 rekeyed,", second.getvalue())
            self.assertEqual(self._read_raw(pm.id), after_first)
