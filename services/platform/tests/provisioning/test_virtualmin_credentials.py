"""
Tests for Virtualmin credential hardening.

Verifies that:
- Server model stores encrypted API credentials correctly
- VirtualminServer stores encrypted API credentials correctly
- Environment variable fallback is removed from _get_credentials
- Credential vault and per-server credentials are the only auth paths
"""

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.credential_vault import CredentialData, CredentialVault
from apps.common.types import Err, Ok
from apps.provisioning.models import Server
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway, get_virtualmin_config
from apps.provisioning.virtualmin_models import VirtualminServer


def create_test_server(**kwargs) -> Server:
    """Helper to create a Server for credential tests."""
    defaults = {
        "name": "cred-test-server",
        "hostname": "cred-test.example.com",
        "server_type": "shared",
        "primary_ip": "10.0.0.1",
        "location": "Bucuresti",
        "datacenter": "DC1",
        "cpu_model": "Intel Xeon",
        "cpu_cores": 4,
        "ram_gb": 16,
        "disk_type": "SSD",
        "disk_capacity_gb": 500,
        "status": "active",
        "os_type": "Ubuntu 22.04 LTS",
        "control_panel": "Virtualmin",
        "monthly_cost": Decimal("200.00"),
        "is_active": True,
    }
    defaults.update(kwargs)
    return Server.objects.create(**defaults)


def create_test_virtualmin_server(**kwargs) -> VirtualminServer:
    """Helper to create a VirtualminServer for gateway credential tests."""
    password = kwargs.pop("_password", "test_pass")
    defaults = {
        "name": "vmin-cred-test",
        "hostname": "vmin-cred.example.com",
        "api_username": "test_user",
    }
    defaults.update(kwargs)
    server = VirtualminServer(**defaults)
    server.set_api_password(password)
    server.save()
    return server


class ServerApiCredentialFieldsTest(TestCase):
    """Test per-server Virtualmin API credential fields on Server model."""

    def test_api_username_defaults_empty(self):
        server = create_test_server()
        self.assertEqual(server.api_username, "")

    def test_api_password_encrypted_defaults_empty(self):
        server = create_test_server()
        self.assertEqual(server._api_password_encrypted, "")

    def test_set_and_get_api_password(self):
        server = create_test_server()
        server.set_api_password("s3cret_pass!")
        server.save()
        server.refresh_from_db()
        self.assertEqual(server.get_api_password(), "s3cret_pass!")

    def test_get_api_password_empty_returns_empty_string(self):
        server = create_test_server()
        self.assertEqual(server.get_api_password(), "")

    def test_set_api_password_empty_clears_field(self):
        server = create_test_server()
        server.set_api_password("initial")
        server.save()
        server.set_api_password("")
        server.save()
        server.refresh_from_db()
        self.assertEqual(server.get_api_password(), "")

    def test_encrypted_password_not_plaintext(self):
        server = create_test_server()
        server.set_api_password("plaintext_secret")
        self.assertNotEqual(server._api_password_encrypted, "plaintext_secret")
        self.assertTrue(len(server._api_password_encrypted) > 0)

    def test_api_username_persists(self):
        server = create_test_server(api_username="vmin_admin")
        server.save()
        server.refresh_from_db()
        self.assertEqual(server.api_username, "vmin_admin")


class GetCredentialsNoEnvFallbackTest(TestCase):
    """Verify that _get_credentials does NOT fall back to environment variables."""

    def _make_gateway(self, server):
        config = VirtualminConfig(server=server)
        return VirtualminGateway(config)

    def test_no_env_fallback_returns_error(self):
        """Without vault or server credentials, _get_credentials returns Err."""
        server = create_test_virtualmin_server(api_username="", _password="")
        gateway = self._make_gateway(server)

        with patch.object(gateway, "_get_credential_vault", return_value=None):
            result = gateway._get_credentials()

        self.assertTrue(result.is_err())
        self.assertIn("No valid credentials found", result.unwrap_err())

    @patch.dict("os.environ", {"VIRTUALMIN_ADMIN_USER": "env_user", "VIRTUALMIN_ADMIN_PASSWORD": "env_pass"})
    def test_env_vars_ignored_when_no_vault_or_server_creds(self):
        """Even with VIRTUALMIN_ADMIN_USER/PASSWORD set, _get_credentials must NOT use them."""
        server = create_test_virtualmin_server(api_username="", _password="")
        gateway = self._make_gateway(server)

        with patch.object(gateway, "_get_credential_vault", return_value=None):
            result = gateway._get_credentials()

        self.assertTrue(result.is_err())

    def test_server_credentials_used(self):
        """VirtualminServer api_username + encrypted password are used."""
        server = create_test_virtualmin_server(api_username="server_user", _password="server_pass")
        gateway = self._make_gateway(server)

        with patch.object(gateway, "_get_credential_vault", return_value=None):
            result = gateway._get_credentials()

        self.assertTrue(result.is_ok())
        username, password = result.unwrap()
        self.assertEqual(username, "server_user")
        self.assertEqual(password, "server_pass")

    def test_vault_credentials_preferred_over_server(self):
        """Credential vault is tried first, before per-server credentials."""
        server = create_test_virtualmin_server(api_username="server_user", _password="server_pass")
        gateway = self._make_gateway(server)

        mock_vault = MagicMock()
        mock_vault.get_credential.return_value = Ok(("vault_user", "vault_pass", {}))

        with patch.object(gateway, "_get_credential_vault", return_value=mock_vault):
            result = gateway._get_credentials()

        self.assertTrue(result.is_ok())
        username, password = result.unwrap()
        self.assertEqual(username, "vault_user")
        self.assertEqual(password, "vault_pass")

    def test_vault_failure_falls_through_to_server_creds(self):
        """When vault fails, server credentials are used as fallback."""
        server = create_test_virtualmin_server(api_username="fallback_user", _password="fallback_pass")
        gateway = self._make_gateway(server)

        mock_vault = MagicMock()
        mock_vault.get_credential.return_value = Err("Vault unavailable")

        with patch.object(gateway, "_get_credential_vault", return_value=mock_vault):
            result = gateway._get_credentials()

        self.assertTrue(result.is_ok())
        username, password = result.unwrap()
        self.assertEqual(username, "fallback_user")
        self.assertEqual(password, "fallback_pass")


class ConfigDictNoEnvCredentialsTest(TestCase):
    """Verify the Virtualmin config dict no longer contains admin_user/admin_password."""

    def test_config_dict_has_no_admin_user_key(self):
        config = get_virtualmin_config()
        self.assertNotIn("admin_user", config)

    def test_config_dict_has_no_admin_password_key(self):
        config = get_virtualmin_config()
        self.assertNotIn("admin_password", config)

    def test_config_dict_retains_pinned_cert(self):
        config = get_virtualmin_config()
        self.assertIn("pinned_cert_sha256", config)


class CredentialVaultRBACTest(TestCase):
    """Verify non-staff users are denied credential access."""

    def test_credential_access_denied_for_non_staff_user(self):
        """Non-staff, non-superuser must be denied credential access."""
        from apps.users.models import User  # noqa: PLC0415

        vault = CredentialVault()

        # Store a credential
        vault.store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier="rbac-test-server",
                username="admin",
                password="s3cret",
            )
        )

        # Create a regular (non-staff, non-superuser) user
        regular_user = User.objects.create_user(
            email="regular@example.com",
            password="testpass123",
        )

        result = vault.get_credential(
            service_type="virtualmin",
            service_identifier="rbac-test-server",
            user=regular_user,
            reason="test",
        )
        self.assertTrue(result.is_err())
        self.assertIn("Access denied", result.unwrap_err())
