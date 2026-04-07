"""Tests for AES-256-GCM encryption module."""

import base64
import os
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from apps.common.encryption import (
    ENCRYPTED_PREFIX,
    VERSIONED_V1_PREFIX,
    VERSIONED_V2_PREFIX,
    DecryptionError,
    _clear_aesgcm_cache,
    decrypt_if_needed,
    decrypt_sensitive_data,
    decrypt_value,
    encrypt_if_sensitive,
    encrypt_sensitive_data,
    encrypt_value,
    generate_backup_codes,
    get_encryption_key,
    get_encryption_keys,
    hash_backup_code,
    is_encrypted,
    verify_backup_code,
)

# Valid AES-256 test key (32 bytes, URL-safe base64)
TEST_KEY = "iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs="
ALT_KEY = "Lp1_hlEyzfJEnH1nUkylaN9c5YvtvOMrXYnc_CEYoSw="


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestEncryptDecryptRoundtrip(SimpleTestCase):
    """Core encrypt/decrypt functionality."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    def test_roundtrip_basic(self) -> None:
        plaintext = "my-secret-totp-key-ABCDEF123456"
        encrypted = encrypt_sensitive_data(plaintext)
        decrypted = decrypt_sensitive_data(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_roundtrip_unicode(self) -> None:
        plaintext = "parolă-secretă-cu-diacritice-și-emoji"
        encrypted = encrypt_sensitive_data(plaintext)
        self.assertEqual(decrypt_sensitive_data(encrypted), plaintext)

    def test_roundtrip_long_data(self) -> None:
        plaintext = "x" * 10000
        encrypted = encrypt_sensitive_data(plaintext)
        self.assertEqual(decrypt_sensitive_data(encrypted), plaintext)

    def test_empty_string_passthrough(self) -> None:
        self.assertEqual(encrypt_sensitive_data(""), "")
        self.assertEqual(decrypt_sensitive_data(""), "")

    def test_encrypted_has_aes_prefix(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        self.assertTrue(encrypted.startswith(ENCRYPTED_PREFIX))

    def test_v1_format_without_aad(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        self.assertTrue(encrypted.startswith(VERSIONED_V1_PREFIX))

    def test_nonce_uniqueness(self) -> None:
        plaintext = "same-value"
        encrypted1 = encrypt_sensitive_data(plaintext)
        encrypted2 = encrypt_sensitive_data(plaintext)
        self.assertNotEqual(encrypted1, encrypted2)
        self.assertEqual(decrypt_sensitive_data(encrypted1), plaintext)
        self.assertEqual(decrypt_sensitive_data(encrypted2), plaintext)

    def test_confidentiality(self) -> None:
        plaintext = "super-secret-api-key-12345"
        encrypted = encrypt_sensitive_data(plaintext)
        raw_part = encrypted[len(VERSIONED_V1_PREFIX) :]
        self.assertNotIn(plaintext, raw_part)
        self.assertNotIn(plaintext, encrypted)


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestDecryptionErrors(SimpleTestCase):
    """Decryption failure scenarios."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    def test_missing_prefix_raises(self) -> None:
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data("not-encrypted-data")

    def test_corrupted_ciphertext_raises(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        corrupted = encrypted[:-4] + "XXXX"
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(corrupted)

    def test_truncated_ciphertext_raises(self) -> None:
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(ENCRYPTED_PREFIX + "dG9vc2hvcnQ=")

    def test_legacy_fernet_ciphertext_rejected(self) -> None:
        fernet_ciphertext = "gAAAAABh1234fake-fernet-ciphertext-data"
        with self.assertRaises(DecryptionError) as ctx:
            decrypt_value(fernet_ciphertext)
        self.assertIn("Legacy Fernet", str(ctx.exception))

    def test_wrong_key_raises(self) -> None:
        _clear_aesgcm_cache()
        with override_settings(ENCRYPTION_KEY=TEST_KEY):
            _clear_aesgcm_cache()
            encrypted = encrypt_sensitive_data("secret")

        _clear_aesgcm_cache()
        with override_settings(ENCRYPTION_KEY=ALT_KEY, ENCRYPTION_KEYS=[ALT_KEY]):
            _clear_aesgcm_cache()
            with self.assertRaises(DecryptionError):
                decrypt_sensitive_data(encrypted)

    def test_tampered_nonce_raises(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        prefix = VERSIONED_V1_PREFIX
        encoded = encrypted[len(prefix) :]
        raw = bytearray(base64.urlsafe_b64decode(encoded))
        raw[0] ^= 0xFF
        tampered = prefix + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(tampered)


class TestKeyValidation(SimpleTestCase):
    """Encryption key loading and validation."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    @override_settings(ENCRYPTION_KEY=None, ENCRYPTION_KEYS=None)
    def test_missing_key_raises(self) -> None:
        _clear_aesgcm_cache()
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(ImproperlyConfigured):
            get_encryption_key()

    @override_settings(ENCRYPTION_KEY="not-valid-base64!!!", ENCRYPTION_KEYS=None)
    def test_invalid_base64_raises(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            get_encryption_key()

    @override_settings(ENCRYPTION_KEY="dG9vc2hvcnQ=", ENCRYPTION_KEYS=None)  # "tooshort" = 8 bytes
    def test_wrong_key_length_raises(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            get_encryption_key()

    @override_settings(ENCRYPTION_KEY=TEST_KEY)
    def test_valid_key_returns_32_bytes(self) -> None:
        key = get_encryption_key()
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestSettingsCompatAPI(SimpleTestCase):
    """Tests for the API surface absorbed from SettingsEncryption."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    def test_is_encrypted_true(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        self.assertTrue(is_encrypted(encrypted))

    def test_is_encrypted_false_plaintext(self) -> None:
        self.assertFalse(is_encrypted("just-a-string"))

    def test_is_encrypted_false_non_string(self) -> None:
        self.assertFalse(is_encrypted(42))
        self.assertFalse(is_encrypted(None))

    def test_encrypt_value_roundtrip(self) -> None:
        encrypted = encrypt_value("api-key-12345")
        self.assertIsNotNone(encrypted)
        self.assertTrue(is_encrypted(encrypted))
        self.assertEqual(decrypt_value(encrypted), "api-key-12345")

    def test_encrypt_value_none(self) -> None:
        self.assertIsNone(encrypt_value(None))

    def test_encrypt_value_non_string(self) -> None:
        encrypted = encrypt_value(42)
        self.assertIsNotNone(encrypted)
        self.assertEqual(decrypt_value(encrypted), "42")

    def test_decrypt_value_plaintext_passthrough(self) -> None:
        self.assertEqual(decrypt_value("not-encrypted"), "not-encrypted")

    def test_decrypt_value_empty(self) -> None:
        self.assertEqual(decrypt_value(""), "")

    def test_decrypt_if_needed_encrypted(self) -> None:
        encrypted = encrypt_sensitive_data("secret")
        self.assertEqual(decrypt_if_needed(encrypted), "secret")

    def test_decrypt_if_needed_plaintext(self) -> None:
        self.assertEqual(decrypt_if_needed("plaintext"), "plaintext")
        self.assertEqual(decrypt_if_needed(42), 42)
        self.assertIsNone(decrypt_if_needed(None))

    def test_encrypt_if_sensitive_true(self) -> None:
        result = encrypt_if_sensitive("secret", is_sensitive=True)
        self.assertTrue(is_encrypted(result))

    def test_encrypt_if_sensitive_false(self) -> None:
        result = encrypt_if_sensitive("not-secret", is_sensitive=False)
        self.assertEqual(result, "not-secret")

    def test_encrypt_if_sensitive_none(self) -> None:
        result = encrypt_if_sensitive(None, is_sensitive=True)
        self.assertIsNone(result)


# ===============================================================================
# KEY VERSIONING TESTS (Issue #87)
# ===============================================================================


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestKeyVersioning(SimpleTestCase):
    """Key versioning wire format and keyring fallback."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    def test_new_encryption_produces_v1_format(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        self.assertTrue(encrypted.startswith(VERSIONED_V1_PREFIX))

    def test_v1_roundtrip(self) -> None:
        encrypted = encrypt_sensitive_data("hello-v1")
        self.assertTrue(encrypted.startswith(VERSIONED_V1_PREFIX))
        self.assertEqual(decrypt_sensitive_data(encrypted), "hello-v1")

    def test_legacy_format_still_decrypts(self) -> None:
        """Pre-versioning 'aes:<payload>' format must still decrypt."""
        # Manually build legacy format (no version tag)
        key = get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, b"legacy-data", None)
        legacy = ENCRYPTED_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

        self.assertFalse(legacy.startswith(VERSIONED_V1_PREFIX))
        self.assertTrue(legacy.startswith(ENCRYPTED_PREFIX))
        self.assertEqual(decrypt_sensitive_data(legacy), "legacy-data")

    @override_settings(ENCRYPTION_KEYS=[TEST_KEY, ALT_KEY])
    def test_keyring_fallback_decrypts_with_old_key(self) -> None:
        """Data encrypted with ALT_KEY should decrypt when ALT_KEY is in keyring."""
        _clear_aesgcm_cache()
        # Encrypt with ALT_KEY directly
        key = base64.urlsafe_b64decode(ALT_KEY)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, b"old-key-data", None)
        encrypted = VERSIONED_V1_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

        # Decrypt with keyring [TEST_KEY, ALT_KEY] — TEST_KEY fails, ALT_KEY succeeds
        self.assertEqual(decrypt_sensitive_data(encrypted), "old-key-data")

    @override_settings(ENCRYPTION_KEYS=[TEST_KEY])
    def test_get_encryption_keys_returns_list(self) -> None:
        _clear_aesgcm_cache()
        keys = get_encryption_keys()
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys[0]), 32)

    @override_settings(ENCRYPTION_KEYS=[TEST_KEY, ALT_KEY])
    def test_new_encryption_always_uses_first_key(self) -> None:
        _clear_aesgcm_cache()
        encrypted = encrypt_sensitive_data("first-key-only")
        # Should decrypt with just TEST_KEY (first in keyring)
        _clear_aesgcm_cache()
        with override_settings(ENCRYPTION_KEYS=[TEST_KEY]):
            _clear_aesgcm_cache()
            self.assertEqual(decrypt_sensitive_data(encrypted), "first-key-only")


# ===============================================================================
# AAD BINDING TESTS (Issue #87)
# ===============================================================================


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestAADBinding(SimpleTestCase):
    """AAD (Associated Authenticated Data) context binding."""

    def setUp(self) -> None:
        _clear_aesgcm_cache()

    def test_aad_produces_v2_format(self) -> None:
        aad = b"customers_payment_methods:bank_details:42"
        encrypted = encrypt_sensitive_data("secret", aad=aad)
        self.assertTrue(encrypted.startswith(VERSIONED_V2_PREFIX))

    def test_aad_roundtrip(self) -> None:
        aad = b"table:field:pk"
        encrypted = encrypt_sensitive_data("aad-data", aad=aad)
        # v2 decryption is self-contained — AAD is embedded
        self.assertEqual(decrypt_sensitive_data(encrypted), "aad-data")

    def test_aad_mismatch_fails_gcm_auth(self) -> None:
        """Ciphertext encrypted with one AAD cannot be decrypted if AAD is tampered."""
        aad = b"customers_payment_methods:bank_details:1"
        encrypted = encrypt_sensitive_data("bank-data", aad=aad)

        # Tamper the embedded AAD in the payload
        raw = base64.urlsafe_b64decode(encrypted[len(VERSIONED_V2_PREFIX) :])
        raw = bytearray(raw)
        # Flip a byte in the AAD region (after the 2-byte length)
        raw[3] ^= 0xFF
        tampered = VERSIONED_V2_PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(tampered)

    def test_no_aad_produces_v1(self) -> None:
        encrypted = encrypt_sensitive_data("no-aad")
        self.assertTrue(encrypted.startswith(VERSIONED_V1_PREFIX))

    def test_v2_with_empty_aad(self) -> None:
        encrypted = encrypt_sensitive_data("empty-aad", aad=b"")
        self.assertTrue(encrypted.startswith(VERSIONED_V2_PREFIX))
        self.assertEqual(decrypt_sensitive_data(encrypted), "empty-aad")

    def test_v2_with_long_aad(self) -> None:
        aad = b"a" * 500
        encrypted = encrypt_sensitive_data("long-aad-data", aad=aad)
        self.assertEqual(decrypt_sensitive_data(encrypted), "long-aad-data")


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestBackupCodes(SimpleTestCase):
    """Backup code functions (hashing, not encryption)."""

    def test_generate_default_count(self) -> None:
        codes = generate_backup_codes()
        self.assertEqual(len(codes), 8)

    def test_generate_custom_count(self) -> None:
        codes = generate_backup_codes(count=4)
        self.assertEqual(len(codes), 4)

    def test_codes_are_8_digits(self) -> None:
        codes = generate_backup_codes()
        for code in codes:
            self.assertEqual(len(code), 8)
            self.assertTrue(code.isdigit())

    def test_codes_are_unique(self) -> None:
        codes = generate_backup_codes(count=100)
        self.assertEqual(len(set(codes)), len(codes))

    def test_hash_and_verify(self) -> None:
        code = "12345678"
        hashed = hash_backup_code(code)
        self.assertTrue(verify_backup_code(code, hashed))
        self.assertFalse(verify_backup_code("87654321", hashed))
