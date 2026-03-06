"""Tests for HKDF-based key derivation module."""

from __future__ import annotations

from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from apps.common.key_derivation import derive_key, get_key_hex


class DeriveKeyTests(SimpleTestCase):
    """Tests for derive_key()."""

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

    def test_unknown_domain_derives_from_secret_key(self) -> None:
        result = derive_key("some-unknown-domain")
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)

    def test_env_var_override_takes_precedence(self) -> None:
        env_value = "A" * 40  # 40 chars, well above minimum
        with patch.dict("os.environ", {"MFA_BACKUP_CODE_PEPPER": env_value}):
            result = derive_key("mfa-backup")
            self.assertEqual(result, env_value.encode("utf-8")[:32])

    def test_env_var_too_short_raises_improperly_configured(self) -> None:
        with patch.dict("os.environ", {"MFA_BACKUP_CODE_PEPPER": "tooshort"}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                derive_key("mfa-backup")
            self.assertIn("MFA_BACKUP_CODE_PEPPER", str(ctx.exception))
            self.assertIn("32", str(ctx.exception))


class GetKeyHexTests(SimpleTestCase):
    """Tests for get_key_hex()."""

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
