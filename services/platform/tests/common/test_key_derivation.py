"""Tests for HKDF-based key derivation module."""

from __future__ import annotations

from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from apps.common.key_derivation import VALID_DOMAINS, derive_key, get_key_hex


class DeriveKeyTests(SimpleTestCase):
    """Tests for derive_key()."""

    def setUp(self) -> None:
        derive_key.cache_clear()

    def tearDown(self) -> None:
        derive_key.cache_clear()

    def test_returns_32_bytes(self) -> None:
        result = derive_key("mfa-backup")
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)

    def test_deterministic_same_domain(self) -> None:
        key1 = derive_key("mfa-backup")
        key2 = derive_key("mfa-backup")
        self.assertEqual(key1, key2)

    def test_different_domains_produce_different_keys(self) -> None:
        key1 = derive_key("mfa-backup")
        key2 = derive_key("unsubscribe")
        self.assertNotEqual(key1, key2)

    def test_unknown_domain_raises_value_error(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            derive_key("some-unknown-domain")
        self.assertIn("Unknown key derivation domain", str(ctx.exception))
        self.assertIn("some-unknown-domain", str(ctx.exception))

    def test_valid_domains_frozenset(self) -> None:
        self.assertIn("mfa-backup", VALID_DOMAINS)
        self.assertIn("unsubscribe", VALID_DOMAINS)
        self.assertIn("siem-hash-chain", VALID_DOMAINS)
        self.assertIn("sensitive-data-hash", VALID_DOMAINS)

    def test_env_var_override_uses_hkdf(self) -> None:
        env_value = "A" * 40  # 40 chars, well above minimum
        with patch.dict("os.environ", {"MFA_BACKUP_CODE_PEPPER": env_value}):
            result = derive_key("mfa-backup")
            self.assertIsInstance(result, bytes)
            self.assertEqual(len(result), 32)
            # HKDF output differs from raw truncation
            self.assertNotEqual(result, env_value.encode("utf-8")[:32])

    def test_env_var_too_short_raises_improperly_configured(self) -> None:
        with patch.dict("os.environ", {"MFA_BACKUP_CODE_PEPPER": "tooshort"}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                derive_key("mfa-backup")
            self.assertIn("MFA_BACKUP_CODE_PEPPER", str(ctx.exception))
            self.assertIn("32", str(ctx.exception))


class GetKeyHexTests(SimpleTestCase):
    """Tests for get_key_hex()."""

    def setUp(self) -> None:
        derive_key.cache_clear()

    def tearDown(self) -> None:
        derive_key.cache_clear()

    def test_returns_hex_string_of_64_chars(self) -> None:
        result = get_key_hex("mfa-backup")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)
        # Verify it's valid hex
        int(result, 16)

    def test_hex_matches_derive_key(self) -> None:
        key_bytes = derive_key("mfa-backup")
        key_hex = get_key_hex("mfa-backup")
        self.assertEqual(key_hex, key_bytes.hex())


class DeriveKeySecretKeyGuardTests(SimpleTestCase):
    """Tests for SECRET_KEY None/empty guards — must raise ImproperlyConfigured."""

    def setUp(self) -> None:
        derive_key.cache_clear()

    def tearDown(self) -> None:
        derive_key.cache_clear()

    def test_none_secret_key_raises_improperly_configured(self) -> None:
        """Must raise ImproperlyConfigured (not AssertionError) for None SECRET_KEY."""
        with self.settings(SECRET_KEY=None):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                derive_key("mfa-backup")
            self.assertIn("SECRET_KEY", str(ctx.exception))
            self.assertNotIsInstance(ctx.exception, AssertionError)

    def test_empty_secret_key_raises_improperly_configured(self) -> None:
        """Must raise ImproperlyConfigured for empty SECRET_KEY (zero-entropy guard)."""
        with self.settings(SECRET_KEY=""):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                derive_key("mfa-backup")
            self.assertIn("SECRET_KEY", str(ctx.exception))
            self.assertNotIsInstance(ctx.exception, AssertionError)
