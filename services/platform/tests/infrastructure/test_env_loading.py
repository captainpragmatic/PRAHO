"""
Tests for .env loading in settings files.

Verifies that dev settings load dotenv while prod/staging do not,
and that the credential vault master key is available in test settings.
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.test import TestCase

# Settings directory: services/platform/config/settings/
_SETTINGS_DIR = Path(__file__).resolve().parents[2] / "config" / "settings"


class TestEnvLoading(TestCase):
    """Tests for .env loading configuration across settings files."""

    def test_dev_settings_has_load_dotenv(self) -> None:
        """Dev settings file contains load_dotenv call."""
        dev_py = _SETTINGS_DIR / "dev.py"
        content = dev_py.read_text()

        self.assertIn("load_dotenv", content)

    def test_prod_settings_does_not_load_dotenv(self) -> None:
        """Prod settings must NOT load .env (secrets come from deployment platform)."""
        prod_py = _SETTINGS_DIR / "prod.py"
        content = prod_py.read_text()

        self.assertNotIn("load_dotenv", content)

    def test_staging_settings_does_not_load_dotenv(self) -> None:
        """Staging settings must NOT load .env."""
        staging_py = _SETTINGS_DIR / "staging.py"
        content = staging_py.read_text()

        self.assertNotIn("load_dotenv", content)

    def test_credential_vault_master_key_available(self) -> None:
        """Test settings have CREDENTIAL_VAULT_MASTER_KEY set."""
        key = getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None)

        self.assertTrue(key, "CREDENTIAL_VAULT_MASTER_KEY must be set in test settings")
