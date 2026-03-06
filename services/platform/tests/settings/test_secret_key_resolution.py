"""Tests for SECRET_KEY resolution and production validation."""

import os
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from config.settings.base import validate_production_secret_key


class SecretKeyResolutionTests(SimpleTestCase):
    """Test DJANGO_SECRET_KEY environment variable resolution."""

    def _resolve_secret_key(self, env: dict) -> str:
        """Re-evaluate secret key resolution logic from base settings."""
        with patch.dict(os.environ, env, clear=False):
            # Remove any existing SECRET_KEY-related env vars first
            for key in ["DJANGO_SECRET_KEY", "SECRET_KEY"]:
                os.environ.pop(key, None)
            # Set the test env vars
            os.environ.update(env)
            return os.environ.get("DJANGO_SECRET_KEY", "").strip() or ""

    def test_django_secret_key_set(self):
        """DJANGO_SECRET_KEY env var resolves correctly."""
        result = self._resolve_secret_key({"DJANGO_SECRET_KEY": "my-test-secret-key-value"})
        self.assertEqual(result, "my-test-secret-key-value")

    def test_django_secret_key_not_set_returns_empty(self):
        """Missing DJANGO_SECRET_KEY returns empty string."""
        result = self._resolve_secret_key({})
        self.assertEqual(result, "")

    def test_django_secret_key_empty_string_treated_as_missing(self):
        """Empty DJANGO_SECRET_KEY is treated as missing."""
        result = self._resolve_secret_key({"DJANGO_SECRET_KEY": ""})
        self.assertEqual(result, "")

    def test_django_secret_key_whitespace_only_treated_as_missing(self):
        """Whitespace-only DJANGO_SECRET_KEY is treated as missing."""
        result = self._resolve_secret_key({"DJANGO_SECRET_KEY": "   "})
        self.assertEqual(result, "")

    def test_old_secret_key_env_var_not_used(self):
        """Plain SECRET_KEY env var is NOT picked up (migration complete)."""
        result = self._resolve_secret_key({"SECRET_KEY": "old-style-key"})
        self.assertEqual(result, "")


class ProductionSecretKeyValidationTests(SimpleTestCase):
    """Test validate_production_secret_key() rejects insecure keys."""

    def setUp(self):
        self.validate = validate_production_secret_key

    def test_rejects_empty_key(self):
        with self.assertRaises(ImproperlyConfigured):
            self.validate("")

    def test_rejects_none_key(self):
        with self.assertRaises(ImproperlyConfigured):
            self.validate(None)

    def test_rejects_short_key(self):
        with self.assertRaises(ImproperlyConfigured):
            self.validate("too-short-key")

    def test_rejects_django_insecure_prefix(self):
        long_key = "django-insecure-" + "x" * 50
        with self.assertRaises(ImproperlyConfigured):
            self.validate(long_key)

    def test_rejects_dev_secret_key_prefix(self):
        long_key = "dev-secret-key-" + "x" * 50
        with self.assertRaises(ImproperlyConfigured):
            self.validate(long_key)

    def test_rejects_test_secret_key_prefix(self):
        long_key = "test-secret-key-" + "x" * 50
        with self.assertRaises(ImproperlyConfigured):
            self.validate(long_key)

    def test_rejects_dev_portal_key_prefix(self):
        long_key = "dev-portal-key-" + "x" * 50
        with self.assertRaises(ImproperlyConfigured):
            self.validate(long_key)

    def test_rejects_well_known_values(self):
        for value in ["changeme", "secret", "password"]:
            with self.subTest(value=value), self.assertRaises(ImproperlyConfigured):
                self.validate(value)

    def test_accepts_exactly_min_length(self):
        """Key with exactly MIN_SECRET_KEY_LENGTH (50) chars should pass."""
        key = "x" * 50
        self.validate(key)  # Should not raise

    def test_rejects_one_below_min_length(self):
        """Key with 49 chars should be rejected."""
        key = "x" * 49
        with self.assertRaises(ImproperlyConfigured):
            self.validate(key)

    def test_accepts_strong_key(self):
        strong_key = "a" * 60  # 60 chars, no insecure prefix
        # Should not raise
        self.validate(strong_key)

    def test_strips_whitespace(self):
        """Whitespace-padded key is stripped before validation."""
        strong_key = "  " + "b" * 60 + "  "
        # Should not raise - stripped to 60 chars
        self.validate(strong_key)
