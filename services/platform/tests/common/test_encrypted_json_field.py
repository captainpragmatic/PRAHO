"""Tests for EncryptedJSONField — AES-256-GCM transparent encryption at rest."""

import json

from django.db import connection
from django.test import TestCase, override_settings

from apps.common.encryption import _clear_aesgcm_cache
from apps.common.fields import _extract_embedded_aad
from apps.customers.models import Customer, CustomerPaymentMethod

# Valid AES-256 test key (matches config/settings/test.py)
TEST_KEY = "iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs="


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldRoundtripTest(TestCase):
    """Core encrypt/decrypt roundtrip through Django ORM."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Test Encryption Customer",
            customer_type="company",
            status="active",
            primary_email="enc@test.com",
            primary_phone="+40712345678",
        )

    def _create_payment_method(self, bank_details: dict | None = None) -> CustomerPaymentMethod:
        return CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Test Bank",
            bank_details=bank_details,
        )

    def test_roundtrip_basic_dict(self) -> None:
        """Bank details dict survives save → refresh_from_db cycle."""
        details = {"bank_name": "Banca Transilvania", "iban": "RO49AAAA1B31007593840000"}
        pm = self._create_payment_method(details)
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details["bank_name"], "Banca Transilvania")
        self.assertEqual(pm.bank_details["iban"], "RO49AAAA1B31007593840000")

    def test_roundtrip_unicode(self) -> None:
        """Romanian diacritics survive encryption roundtrip."""
        details = {"bank_name": "Banca Românească", "bank_address": "Str. Ștefan cel Mare"}
        pm = self._create_payment_method(details)
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details["bank_name"], "Banca Românească")
        self.assertEqual(pm.bank_details["bank_address"], "Str. Ștefan cel Mare")

    def test_null_bank_details_preserved(self) -> None:
        """NULL bank_details stays NULL (not encrypted)."""
        pm = self._create_payment_method(None)
        pm.refresh_from_db()
        self.assertIsNone(pm.bank_details)

    def test_empty_dict_roundtrip(self) -> None:
        """Empty dict {} survives roundtrip (not treated as None)."""
        pm = self._create_payment_method({})
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details, {})

    def test_complex_nested_dict(self) -> None:
        """Nested structures survive encryption roundtrip."""
        details = {
            "bank_name": "BRD",
            "iban": "RO49BRDE445SV97356100000",
            "swift_code": "BRDEROBU",
            "account_holder": "Test SRL",
            "bank_address": "Str. Ion Mihalache 1-7, București",
        }
        pm = self._create_payment_method(details)
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details, details)

    def test_data_is_encrypted_in_database(self) -> None:
        """Raw DB value is an encrypted string, not plaintext JSON."""
        details = {"iban": "RO49AAAA1B31007593840000", "bank_name": "BT"}
        pm = self._create_payment_method(details)

        # Read raw value from DB bypassing field decryption
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            raw_value = cursor.fetchone()[0]

        # Raw value should contain encrypted prefix (stored as JSON string in DB)
        # SQLite stores it as text; PostgreSQL as jsonb string
        raw_str = raw_value if isinstance(raw_value, str) else str(raw_value)
        self.assertIn("aes:", raw_str)
        # Plaintext IBAN must NOT appear in raw DB value
        self.assertNotIn("RO49AAAA", raw_str)

    def test_update_preserves_encryption(self) -> None:
        """Updating bank_details re-encrypts with fresh nonce."""
        pm = self._create_payment_method({"iban": "RO49AAAA1B31007593840000"})
        pm.bank_details = {"iban": "RO49BBBB1B31007593840000"}
        pm.save()
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details["iban"], "RO49BBBB1B31007593840000")

    def test_queryset_returns_decrypted_data(self) -> None:
        """QuerySet iteration returns decrypted dicts."""
        self._create_payment_method({"bank_name": "ING"})
        pm = CustomerPaymentMethod.objects.filter(customer=self.customer).first()
        self.assertIsNotNone(pm)
        assert pm is not None
        self.assertEqual(pm.bank_details["bank_name"], "ING")


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldLegacyDataTest(TestCase):
    """Backward compatibility with pre-existing unencrypted data."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Legacy Customer",
            customer_type="individual",
            status="active",
            primary_email="legacy@test.com",
            primary_phone="+40712345679",
        )

    def test_legacy_unencrypted_dict_still_readable(self) -> None:
        """Pre-existing plaintext JSON dicts are returned as-is on read."""
        # Insert plaintext JSON directly (simulating pre-encryption data)
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Legacy Bank",
            bank_details=None,  # Create first with null
        )
        # Write plaintext JSON directly to DB, bypassing field encryption
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                ['{"bank_name": "Legacy BT", "iban": "RO49BTRL1B31007593840001"}', pm.id],
            )

        pm.refresh_from_db()
        # Should be readable as a dict (backward compat)
        self.assertIsInstance(pm.bank_details, dict)
        self.assertEqual(pm.bank_details["bank_name"], "Legacy BT")

    def test_legacy_data_encrypted_on_resave(self) -> None:
        """Legacy plaintext data gets encrypted when re-saved."""
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Resave Bank",
            bank_details=None,
        )
        # Write plaintext directly
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                ['{"iban": "RO49AAAA1B31007593840000"}', pm.id],
            )
        pm.refresh_from_db()
        # Re-save to trigger encryption
        pm.save()

        # Verify raw DB now contains encrypted data
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            raw_value = cursor.fetchone()[0]

        raw_str = raw_value if isinstance(raw_value, str) else str(raw_value)
        self.assertIn("aes:", raw_str)
        self.assertNotIn("RESAVE", raw_str)


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldAADTest(TestCase):
    """AAD context binding prevents ciphertext transplant attacks."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()
        self.customer = Customer.objects.create(
            name="AAD Test Customer",
            customer_type="company",
            status="active",
            primary_email="aad@test.com",
            primary_phone="+40712345680",
        )

    def test_new_encryption_uses_v2_format(self) -> None:
        """Newly saved bank_details should use v2 AAD-bound format."""
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="AAD Bank",
            bank_details={"iban": "RO49AAAA1B31007593840000"},
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            raw_value = cursor.fetchone()[0]

        raw_str = raw_value if isinstance(raw_value, str) else str(raw_value)
        self.assertIn("aes:v2:", raw_str)

    def test_aad_embedded_includes_table_and_field(self) -> None:
        """Embedded AAD must include table name and field name for context binding."""
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="AAD Context",
            bank_details={"iban": "RO49AAAA1111111111111111"},
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            raw = cursor.fetchone()[0]

        raw_str = raw if isinstance(raw, str) else str(raw)
        encrypted_str = json.loads(raw_str) if raw_str.startswith('"') else raw_str
        aad = _extract_embedded_aad(encrypted_str)
        self.assertIsNotNone(aad)
        aad_str = aad.decode() if aad else ""
        # AAD contains table:field: (pk may be empty on INSERT for auto-increment)
        self.assertIn("customer_payment_methods", aad_str)
        self.assertIn("bank_details", aad_str)

    def test_resaved_aad_includes_pk(self) -> None:
        """After re-save, AAD includes the pk for full context binding."""
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Resave AAD",
            bank_details={"iban": "RO49AAAA1111111111111111"},
        )
        # Re-save: now pk is known
        pm.save()

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            raw = cursor.fetchone()[0]

        raw_str = raw if isinstance(raw, str) else str(raw)
        encrypted_str = json.loads(raw_str) if raw_str.startswith('"') else raw_str
        aad = _extract_embedded_aad(encrypted_str)
        self.assertIsNotNone(aad)
        aad_str = aad.decode() if aad else ""
        self.assertIn(str(pm.id), aad_str)

    def test_roundtrip_with_aad(self) -> None:
        """Normal save/load cycle works with AAD binding."""
        details = {"bank_name": "BRD", "iban": "RO49BRDE445SV97356100000"}
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="AAD Roundtrip",
            bank_details=details,
        )
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details, details)
