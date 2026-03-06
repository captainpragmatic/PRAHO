"""Tests for AES-256-GCM encryption module."""

import base64
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

import apps.common.encryption as enc
from apps.common.encryption import (
    ENCRYPTED_PREFIX,
    DecryptionError,
    decrypt_if_needed,
    decrypt_sensitive_data,
    decrypt_value,
    encrypt_if_sensitive,
    encrypt_sensitive_data,
    encrypt_value,
    generate_backup_codes,
    get_encryption_key,
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

    def test_nonce_uniqueness(self) -> None:
        """Encrypting the same value twice must produce different ciphertext."""
        plaintext = "same-value"
        encrypted1 = encrypt_sensitive_data(plaintext)
        encrypted2 = encrypt_sensitive_data(plaintext)
        self.assertNotEqual(encrypted1, encrypted2)
        # Both must decrypt to the same plaintext
        self.assertEqual(decrypt_sensitive_data(encrypted1), plaintext)
        self.assertEqual(decrypt_sensitive_data(encrypted2), plaintext)

    def test_confidentiality(self) -> None:
        """Ciphertext must NOT contain the plaintext substring."""
        plaintext = "super-secret-api-key-12345"
        encrypted = encrypt_sensitive_data(plaintext)
        # Remove prefix for raw check
        raw_part = encrypted[len(ENCRYPTED_PREFIX) :]
        self.assertNotIn(plaintext, raw_part)
        self.assertNotIn(plaintext, encrypted)


@override_settings(ENCRYPTION_KEY=TEST_KEY)
class TestDecryptionErrors(SimpleTestCase):
    """Decryption failure scenarios."""

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

    @override_settings(ENCRYPTION_KEY=ALT_KEY)
    def test_wrong_key_raises(self) -> None:
        # Encrypt with TEST_KEY, then try to decrypt with ALT_KEY
        with override_settings(ENCRYPTION_KEY=TEST_KEY):
            # Reset cached AESGCM
            enc._cached_aesgcm = None
            encrypted = encrypt_sensitive_data("secret")

        # Now decrypt with ALT_KEY
        enc._cached_aesgcm = None
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(encrypted)

    def test_tampered_nonce_raises(self) -> None:
        encrypted = encrypt_sensitive_data("test")
        encoded = encrypted[len(ENCRYPTED_PREFIX) :]
        raw = bytearray(base64.urlsafe_b64decode(encoded))
        raw[0] ^= 0xFF  # Flip first byte of nonce
        tampered = ENCRYPTED_PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(DecryptionError):
            decrypt_sensitive_data(tampered)


class TestKeyValidation(SimpleTestCase):
    """Encryption key loading and validation."""

    @override_settings(ENCRYPTION_KEY=None)
    def test_missing_key_raises(self) -> None:
        enc._cached_aesgcm = None
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(ImproperlyConfigured):
            get_encryption_key()

    @override_settings(ENCRYPTION_KEY="not-valid-base64!!!")
    def test_invalid_base64_raises(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            get_encryption_key()

    @override_settings(ENCRYPTION_KEY="dG9vc2hvcnQ=")  # "tooshort" = 8 bytes
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
        # Very high probability of uniqueness for 100 8-digit codes
        self.assertEqual(len(set(codes)), len(codes))

    def test_hash_and_verify(self) -> None:
        code = "12345678"
        hashed = hash_backup_code(code)
        self.assertTrue(verify_backup_code(code, hashed))
        self.assertFalse(verify_backup_code("87654321", hashed))
