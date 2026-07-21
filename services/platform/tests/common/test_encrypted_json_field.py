"""Tests for EncryptedJSONField — AES-256-GCM transparent encryption at rest."""

import json
from types import SimpleNamespace

from django.db import DatabaseError, connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings

from apps.common.encryption import (
    VERSIONED_V2_PREFIX,
    DecryptionError,
    EncryptionError,
    _clear_aesgcm_cache,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)
from apps.common.fields import EncryptedJSONField, _extract_embedded_aad
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
    """Payment data rejects unmigrated plaintext instead of treating it as healthy."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Legacy Customer",
            customer_type="individual",
            status="active",
            primary_email="legacy@test.com",
            primary_phone="+40712345679",
        )

    def test_legacy_unencrypted_dict_fails_loud(self) -> None:
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

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=pm.pk)

    def test_failed_read_preserves_legacy_ciphertext_evidence(self) -> None:
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
        with connection.cursor() as cursor:
            cursor.execute("SELECT bank_details FROM customer_payment_methods WHERE id = %s", [pm.id])
            before = cursor.fetchone()[0]

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=pm.pk)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            after = cursor.fetchone()[0]
        self.assertEqual(after, before)

    def test_corrupt_ciphertext_fails_loud_and_remains_untouched(self) -> None:
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Corrupt Bank",
            bank_details=None,
        )
        corrupt = json.dumps("aes:v2:!!!garbage!!!")
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [corrupt, pm.id],
            )

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=pm.pk)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [pm.id],
            )
            after = cursor.fetchone()[0]
        self.assertEqual(after, corrupt)


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

    def test_first_insert_aad_uses_exact_row_encryption_identity(self) -> None:
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
        self.assertEqual(
            aad,
            f"customer_payment_methods:bank_details:{pm.encryption_context_id}".encode(),
        )

    def test_same_field_cross_row_transplant_fails_for_models_and_values(self) -> None:
        source = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Source",
            bank_details={"iban": "RO49SOURCE11111111111111"},
        )
        target = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Target",
            bank_details={"iban": "RO49TARGET11111111111111"},
        )

        with connection.cursor() as cursor:
            cursor.execute("SELECT bank_details FROM customer_payment_methods WHERE id = %s", [source.id])
            source_raw = cursor.fetchone()[0]
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [source_raw, target.id],
            )

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=target.pk)
        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.filter(pk=target.pk).values_list("bank_details", flat=True).get()

    def test_row_encryption_identity_is_database_immutable(self) -> None:
        source = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Identity source",
            bank_details={"iban": "RO49SOURCE11111111111111"},
        )
        target = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Identity target",
            bank_details={"iban": "RO49TARGET11111111111111"},
        )

        with self.assertRaises(DatabaseError), transaction.atomic():
            CustomerPaymentMethod.objects.filter(pk=target.pk).update(
                encryption_context_id=source.encryption_context_id
            )
        target.refresh_from_db()
        self.assertNotEqual(target.encryption_context_id, source.encryption_context_id)

    def test_values_and_values_list_preserve_valid_plaintext_shape(self) -> None:
        details = {"bank_name": "BT", "iban": "RO49VALUE111111111111111"}
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Projection",
            bank_details=details,
        )

        projected = CustomerPaymentMethod.objects.filter(pk=pm.pk).values("bank_details").get()
        listed = CustomerPaymentMethod.objects.filter(pk=pm.pk).values_list("bank_details", flat=True).get()
        self.assertEqual(projected["bank_details"], details)
        self.assertEqual(listed, details)

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


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldRequireV2Test(TestCase):
    """require_v2 rejects v1/plaintext downgrade (review H1)."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()
        self.customer = Customer.objects.create(
            name="RequireV2 Customer",
            customer_type="company",
            status="active",
            primary_email="rv2@test.com",
            primary_phone="+40712345681",
        )
        self.field = CustomerPaymentMethod._meta.get_field("bank_details")

    def _write_raw(self, pk: int, raw_json_value: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [raw_json_value, pk],
            )

    def test_v2_value_is_accepted(self) -> None:
        details = {"bank_name": "BT", "iban": "RO49BTRL1B31007593840001"}
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name="V2", bank_details=details
        )
        pm.refresh_from_db()
        self.assertEqual(pm.bank_details, details)

    def test_v1_ciphertext_is_rejected(self) -> None:
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name="V1", bank_details=None
        )
        # Craft a v1 ciphertext (no AAD) and write it raw, simulating a downgrade.
        v1_cipher = encrypt_sensitive_data(json.dumps({"iban": "RO00DOWNGRADE"}))
        self.assertTrue(v1_cipher.startswith("aes:v1:"))
        self._write_raw(pm.id, json.dumps(v1_cipher))

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=pm.pk)

    def test_plaintext_is_rejected(self) -> None:
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name="Plain", bank_details=None
        )
        self._write_raw(pm.id, '{"iban": "RO00PLAINTEXT"}')

        with self.assertRaises(DecryptionError):
            CustomerPaymentMethod.objects.get(pk=pm.pk)

    def test_customer_payment_method_requires_v2(self) -> None:
        self.assertTrue(self.field.require_v2)


# ===============================================================================
# F3 — AAD isolation: per-field binding, no shared/thread-local state
# ===============================================================================


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldAADIsolationTest(SimpleTestCase):
    """Each field binds AAD to its OWN table:field with no cross-field contamination."""

    def test_pre_save_binds_each_field_to_its_own_aad(self) -> None:
        """Two encrypted fields on one instance must each embed their own table:field AAD.

        Regression for the old shared thread-local: field B's pre_save overwrote field A's
        stashed AAD, so A was encrypted under B's context (and B lost its binding). With
        per-field encryption in pre_save there is no shared state to corrupt.
        """

        inst = SimpleNamespace(
            _meta=SimpleNamespace(db_table="iso_table"),
            pk=7,
            field_a={"secret": "a-value"},
            field_b={"secret": "b-value"},
        )

        fa = EncryptedJSONField()
        fa.set_attributes_from_name("field_a")
        fb = EncryptedJSONField()
        fb.set_attributes_from_name("field_b")
        # Django calls ALL fields' pre_save first, THEN prepares values — replicate that order
        # so a shared slot would be observably clobbered.
        prepped_a = fa.pre_save(inst, add=True)
        prepped_b = fb.pre_save(inst, add=True)

        self.assertTrue(prepped_a.startswith(VERSIONED_V2_PREFIX))
        self.assertTrue(prepped_b.startswith(VERSIONED_V2_PREFIX))

        aad_a = _extract_embedded_aad(prepped_a)
        aad_b = _extract_embedded_aad(prepped_b)
        assert aad_a is not None and aad_b is not None
        self.assertTrue(aad_a.startswith(b"iso_table:field_a:"))
        self.assertTrue(aad_b.startswith(b"iso_table:field_b:"))
        # Each decrypts to its OWN value — proves no cross-field corruption.
        self.assertEqual(json.loads(decrypt_sensitive_data(prepped_a)), {"secret": "a-value"})
        self.assertEqual(json.loads(decrypt_sensitive_data(prepped_b)), {"secret": "b-value"})


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class EncryptedJSONFieldWritePathTest(TestCase):
    """Write paths that bypass pre_save cannot bind AAD — fail loud instead of silent v1."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()
        self.customer = Customer.objects.create(
            name="WritePath Customer",
            customer_type="company",
            status="active",
            primary_email="wp@test.com",
            primary_phone="+40712345682",
        )

    def test_queryset_update_rejects_unbound_plaintext(self) -> None:
        pm = CustomerPaymentMethod.objects.create(
            customer=self.customer, method_type="bank_transfer", display_name="U", bank_details={}
        )
        with self.assertRaises(EncryptionError), transaction.atomic():
            CustomerPaymentMethod.objects.filter(pk=pm.pk).update(bank_details={"bank_name": "BT"})

        pm.refresh_from_db()
        self.assertEqual(pm.bank_details, {})

    def test_queryset_update_rejects_prebuilt_ciphertext(self) -> None:
        source = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Source",
            bank_details={"iban": "RO49SOURCE11111111111111"},
        )
        target = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="bank_transfer",
            display_name="Target",
            bank_details={"iban": "RO49TARGET11111111111111"},
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT bank_details FROM customer_payment_methods WHERE id = %s",
                [source.pk],
            )
            raw = cursor.fetchone()[0]
        wire = json.loads(raw) if isinstance(raw, str) and raw.startswith('"') else raw

        with self.assertRaises(EncryptionError), transaction.atomic():
            CustomerPaymentMethod.objects.filter(pk=target.pk).update(
                bank_details=wire
            )

    def test_bulk_create_roundtrips_encrypted_v2(self) -> None:
        """bulk_create DOES run pre_save, so values are encrypted (v2) and round-trip."""
        ibans = ["RO49AAAA1B31007593840000", "RO49BBBB1B31007593840000"]
        objs = [
            CustomerPaymentMethod(
                customer=self.customer,
                method_type="bank_transfer",
                display_name=f"B{i}",
                bank_details={"bank_name": "BT", "iban": ibans[i]},
            )
            for i in range(2)
        ]
        CustomerPaymentMethod.objects.bulk_create(objs)
        rows = list(
            CustomerPaymentMethod.objects.filter(customer=self.customer, display_name__startswith="B").order_by(
                "display_name"
            )
        )
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0].encryption_context_id, rows[1].encryption_context_id)
        self.assertEqual(rows[0].bank_details["iban"], ibans[0])
        self.assertEqual(rows[1].bank_details["iban"], ibans[1])
        with connection.cursor() as cursor:
            cursor.execute("SELECT bank_details FROM customer_payment_methods WHERE id = %s", [rows[0].id])
            raw = cursor.fetchone()[0]
        raw_str = raw if isinstance(raw, str) else str(raw)
        wire = json.loads(raw_str) if raw_str.startswith('"') else raw_str
        self.assertEqual(
            _extract_embedded_aad(wire),
            f"customer_payment_methods:bank_details:{rows[0].encryption_context_id}".encode(),
        )


# ===============================================================================
# F5 — deconstruct() preserves the security-relevant require_v2 flag
# ===============================================================================


class EncryptedJSONFieldDeconstructTest(SimpleTestCase):
    """require_v2 is a security option; Field.clone()/historical models must not lose it."""

    def test_deconstruct_preserves_require_v2_when_true(self) -> None:
        field = EncryptedJSONField(require_v2=True)
        _name, path, _args, kwargs = field.deconstruct()
        self.assertEqual(path, "apps.common.fields.EncryptedJSONField")
        self.assertTrue(kwargs.get("require_v2"))

    def test_deconstruct_omits_require_v2_when_default(self) -> None:
        field = EncryptedJSONField()
        _name, _path, _args, kwargs = field.deconstruct()
        self.assertNotIn("require_v2", kwargs)

    def test_deconstruct_preserves_aad_context_field(self) -> None:
        field = EncryptedJSONField(aad_context_field="encryption_context_id")
        _name, _path, _args, kwargs = field.deconstruct()
        self.assertEqual(kwargs["aad_context_field"], "encryption_context_id")
