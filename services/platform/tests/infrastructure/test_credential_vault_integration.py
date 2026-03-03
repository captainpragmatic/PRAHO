"""
Tests for credential vault integration with infrastructure provider helpers.

Verifies that store_provider_token() and get_provider_token() correctly
interact with the CredentialVault for cloud provider API tokens.
"""

from __future__ import annotations

import os
from unittest.mock import patch

from django.test import TestCase

from apps.common.credential_vault import CredentialAccessLog, EncryptedCredential
from apps.infrastructure.models import CloudProvider
from apps.infrastructure.provider_config import get_provider_token, store_provider_token


class TestStoreProviderToken(TestCase):
    """Tests for store_provider_token() helper."""

    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="TST",
            is_active=True,
        )

    def test_stores_token_in_vault(self) -> None:
        """Storing a token creates an EncryptedCredential record."""
        result = store_provider_token(self.provider, "test-api-token-123")

        self.assertTrue(result.is_ok())
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="cloud_provider",
                service_identifier=result.unwrap(),
            ).exists()
        )

    def test_updates_existing_token(self) -> None:
        """Storing a token twice increments rotation_count."""
        store_provider_token(self.provider, "token-v1")
        result = store_provider_token(self.provider, "token-v2")

        self.assertTrue(result.is_ok())
        cred = EncryptedCredential.objects.get(
            service_type="cloud_provider",
            service_identifier=result.unwrap(),
        )
        self.assertEqual(cred.rotation_count, 1)

    def test_returns_credential_identifier(self) -> None:
        """Returned identifier matches expected format."""
        result = store_provider_token(self.provider, "token-abc")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), f"cloud_provider_{self.provider.code}")

    def test_uses_existing_credential_identifier(self) -> None:
        """If provider already has a credential_identifier, it is reused."""
        self.provider.credential_identifier = "custom_id"
        self.provider.save()

        result = store_provider_token(self.provider, "token-xyz")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "custom_id")


class TestGetProviderToken(TestCase):
    """Tests for get_provider_token() helper."""

    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="TST",
            is_active=True,
        )

    def test_retrieves_from_vault(self) -> None:
        """Token stored in vault can be retrieved."""
        store_result = store_provider_token(self.provider, "my-secret-token")
        self.provider.credential_identifier = store_result.unwrap()
        self.provider.save()

        result = get_provider_token(self.provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "my-secret-token")

    def test_fallback_to_env_var(self) -> None:
        """Falls back to HCLOUD_TOKEN env var when no vault credential."""
        self.provider.credential_identifier = ""
        self.provider.save()

        with patch.dict(os.environ, {"HCLOUD_TOKEN": "env-token-fallback"}):
            result = get_provider_token(self.provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "env-token-fallback")

    def test_returns_error_when_no_token(self) -> None:
        """Returns Err when neither vault nor env var has a token."""
        self.provider.credential_identifier = ""
        self.provider.save()

        with patch.dict(os.environ, {}, clear=False):
            # Ensure HCLOUD_TOKEN is not set
            env = os.environ.copy()
            env.pop("HCLOUD_TOKEN", None)
            with patch.dict(os.environ, env, clear=True):
                result = get_provider_token(self.provider)

        self.assertTrue(result.is_err())

    def test_vault_takes_priority_over_env(self) -> None:
        """Vault credential takes priority over environment variable."""
        store_result = store_provider_token(self.provider, "vault-token")
        self.provider.credential_identifier = store_result.unwrap()
        self.provider.save()

        with patch.dict(os.environ, {"HCLOUD_TOKEN": "env-token"}):
            result = get_provider_token(self.provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "vault-token")


class TestRoundTrip(TestCase):
    """Tests for store + retrieve round-trip and audit logging."""

    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="TST",
            is_active=True,
        )

    def test_store_and_retrieve_round_trip(self) -> None:
        """Token survives a full store -> retrieve cycle."""
        token = "round-trip-secret-token-12345"
        store_result = store_provider_token(self.provider, token)
        self.provider.credential_identifier = store_result.unwrap()
        self.provider.save()

        result = get_provider_token(self.provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), token)

    def test_audit_log_created(self) -> None:
        """Store + retrieve creates CredentialAccessLog entries."""
        store_result = store_provider_token(self.provider, "audit-token")
        self.provider.credential_identifier = store_result.unwrap()
        self.provider.save()

        # Store creates one log entry
        initial_count = CredentialAccessLog.objects.count()
        self.assertGreaterEqual(initial_count, 1)

        # Retrieve creates another
        get_provider_token(self.provider)
        self.assertGreater(CredentialAccessLog.objects.count(), initial_count)
