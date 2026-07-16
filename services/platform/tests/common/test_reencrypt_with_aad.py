"""Tests for the reencrypt_with_aad management command (v1/legacy/plaintext → v2 AAD)."""

import json
from io import StringIO
from unittest.mock import patch

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
from apps.customers.models import Customer, CustomerPaymentMethod

TEST_KEY = "iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs="
VALID = {"bank_name": "BT", "iban": "RO49AAAA1B31007593840000"}


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class ReencryptWithAadCommandTest(TestCase):
    """The command must be idempotent, cover soft-deleted rows, and fail loud on corruption."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()
        self.customer = Customer.objects.create(
            name="Reencrypt Customer",
            customer_type="company",
            status="active",
            primary_email="re@test.com",
            primary_phone="+40712345683",
        )

    def _make_pm(self, display: str = "PM") -> CustomerPaymentMethod:
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

    def _seed_v1(self, pk: int, value: dict = VALID) -> None:
        wire = encrypt_sensitive_data(json.dumps(value))  # v1 (no AAD)
        assert wire.startswith("aes:v1:")
        self._write_raw(pk, wire)

    def test_v1_row_migrated_to_v2_with_aad(self) -> None:
        pm = self._make_pm()
        self._seed_v1(pm.id)
        call_command("reencrypt_with_aad", stdout=StringIO())
        stored = self._read_raw(pm.id)
        self.assertIsInstance(stored, str)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(json.loads(decrypt_sensitive_data(stored)), VALID)

    def test_idempotent_second_run_is_a_true_noop(self) -> None:
        pm = self._make_pm()
        self._seed_v1(pm.id)
        call_command("reencrypt_with_aad", stdout=StringIO())
        first = self._read_raw(pm.id)
        out = StringIO()
        call_command("reencrypt_with_aad", stdout=out)
        second = self._read_raw(pm.id)
        # A v2 row must be skipped, not re-encrypted with a fresh nonce.
        self.assertEqual(first, second)
        self.assertIn("0 migrated", out.getvalue())

    def test_soft_deleted_row_is_migrated(self) -> None:
        pm = self._make_pm()
        pm.soft_delete()  # sets deleted_at; row physically remains
        self._seed_v1(pm.id)  # seed AFTER soft-delete so no save() clobbers it
        call_command("reencrypt_with_aad", stdout=StringIO())
        stored = self._read_raw(pm.id)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))

    def test_corrupt_row_flagged_not_overwritten_and_nonzero_exit(self) -> None:
        pm = self._make_pm()
        corrupt_wire = "aes:v1:!!!notbase64!!!"  # cannot decrypt
        self._write_raw(pm.id, corrupt_wire)
        with self.assertRaises(CommandError):
            call_command("reencrypt_with_aad", stdout=StringIO(), stderr=StringIO())
        self.assertEqual(self._read_raw(pm.id), corrupt_wire)  # untouched

    def test_corrupt_row_tolerated_with_allow_corrupt(self) -> None:
        pm = self._make_pm()
        self._write_raw(pm.id, "aes:v1:!!!notbase64!!!")
        # Must not raise when explicitly allowed.
        call_command("reencrypt_with_aad", "--allow-corrupt", stdout=StringIO(), stderr=StringIO())

    def test_dry_run_writes_nothing(self) -> None:
        pm = self._make_pm()
        self._seed_v1(pm.id)
        before = self._read_raw(pm.id)
        call_command("reencrypt_with_aad", "--dry-run", stdout=StringIO())
        self.assertEqual(self._read_raw(pm.id), before)

    def test_plaintext_row_migrated_to_v2(self) -> None:
        pm = self._make_pm()
        self._write_raw(pm.id, VALID)  # plaintext JSON dict, no aes: prefix
        call_command("reencrypt_with_aad", stdout=StringIO())
        stored = self._read_raw(pm.id)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(json.loads(decrypt_sensitive_data(stored)), VALID)

    def test_batch_zero_rejected(self) -> None:
        with self.assertRaises(CommandError):
            call_command("reencrypt_with_aad", "--batch", "0", stdout=StringIO())

    def test_v2_corrupt_row_flagged_not_skipped_as_healthy(self) -> None:
        """A v2-shaped but undecryptable blob must be flagged corrupt, not counted 'already v2'."""
        pm = self._make_pm()
        self._write_raw(pm.id, "aes:v2:!!!garbage!!!")  # v2 prefix, cannot decrypt
        with self.assertRaises(CommandError):
            call_command("reencrypt_with_aad", stdout=StringIO(), stderr=StringIO())
        self.assertEqual(self._read_raw(pm.id), "aes:v2:!!!garbage!!!")  # untouched

    def test_transplanted_v2_row_flagged_not_skipped_as_healthy(self) -> None:
        """A v2 blob bound to a DIFFERENT table:field decrypts but reads back None under require_v2.

        The command must flag it (it can't safely report 'already v2'), not skip it as healthy.
        """
        pm = self._make_pm()
        wrong = encrypt_sensitive_data(json.dumps(VALID), aad=b"other_table:other_field:99")
        self.assertTrue(wrong.startswith(VERSIONED_V2_PREFIX))
        self._write_raw(pm.id, wrong)
        with self.assertRaises(CommandError):
            call_command("reencrypt_with_aad", stdout=StringIO(), stderr=StringIO())
        self.assertEqual(self._read_raw(pm.id), wrong)  # untouched (not migrated, not reported healthy)

    def test_cas_retries_and_resolves_after_a_stale_read(self) -> None:
        """A first CAS miss (stale read) is retried against the row's real current value and migrates."""
        from apps.common.management.commands.reencrypt_with_aad import Command  # noqa: PLC0415

        pm = self._make_pm()
        self._seed_v1(pm.id)  # DB holds the real v1
        # A different valid v1 (fresh nonce) — decryptable, but its bytes don't match the DB,
        # so the first CAS misses; the retry re-reads the real value (via the un-patched
        # _read_one) and migrates it.
        stale_raw = json.dumps(encrypt_sensitive_data(json.dumps(VALID)))
        pk = pm.id

        def fake_read_batch(
            _self: Command, _q_table: str, _q_col: str, _q_pk: str, last_pk: object, _batch: int
        ) -> list[tuple[object, object]]:
            return [(pk, stale_raw)] if last_pk is None else []

        with patch.object(Command, "_read_batch", fake_read_batch):
            call_command("reencrypt_with_aad", stdout=StringIO())

        stored = self._read_raw(pm.id)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith(VERSIONED_V2_PREFIX))  # retry resolved it
        self.assertEqual(json.loads(decrypt_sensitive_data(stored)), VALID)

    def test_cas_unresolved_raises_when_row_keeps_changing(self) -> None:
        """If every attempt's CAS misses (row keeps changing), the command exits non-zero, un-migrated."""
        from apps.common.management.commands.reencrypt_with_aad import Command  # noqa: PLC0415

        pm = self._make_pm()
        self._seed_v1(pm.id)
        stale_raw = json.dumps(encrypt_sensitive_data(json.dumps(VALID)))  # never matches the DB
        pk = pm.id

        def fake_read_batch(
            _self: Command, _q_table: str, _q_col: str, _q_pk: str, last_pk: object, _batch: int
        ) -> list[tuple[object, object]]:
            return [(pk, stale_raw)] if last_pk is None else []

        def fake_read_one(_self: Command, _q_table: str, _q_col: str, _q_pk: str, _pk: object) -> object:
            return stale_raw  # every re-read is still stale → CAS always misses

        with (
            patch.object(Command, "_read_batch", fake_read_batch),
            patch.object(Command, "_read_one", fake_read_one),
            self.assertRaises(CommandError),
        ):
            call_command("reencrypt_with_aad", stdout=StringIO(), stderr=StringIO())

        stored = self._read_raw(pm.id)
        assert isinstance(stored, str)
        self.assertTrue(stored.startswith("aes:v1:"))  # never migrated (real value untouched)
