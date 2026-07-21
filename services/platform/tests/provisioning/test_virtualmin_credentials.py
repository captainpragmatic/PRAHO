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
from apps.provisioning.virtualmin_forms import VirtualminServerForm
from apps.provisioning.virtualmin_gateway import (
    VirtualminConfig,
    VirtualminGateway,
    get_virtualmin_config,
    resolve_server_credentials,
)
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

    def test_vault_not_found_falls_through_to_server_creds(self):
        """A genuine vault MISS (no entry) falls back to the encrypted server field — the intended
        path for manually-registered servers that were never migrated into the vault."""
        server = create_test_virtualmin_server(api_username="fallback_user", _password="fallback_pass")
        gateway = self._make_gateway(server)

        mock_vault = MagicMock()
        # Matches CredentialVault.get_credential's real not-found message (credential_vault.py).
        mock_vault.get_credential.return_value = Err("Credential not found: virtualmin:vmin-cred.example.com")

        with patch.object(gateway, "_get_credential_vault", return_value=mock_vault):
            result = gateway._get_credentials()

        self.assertTrue(result.is_ok())
        username, password = result.unwrap()
        self.assertEqual(username, "fallback_user")
        self.assertEqual(password, "fallback_pass")

    def test_vault_unavailable_is_terminal_no_field_fallback(self):
        """A vault error that is NOT a genuine miss — outage, expiry, access-denied, decryption —
        must be TERMINAL: the resolver must NOT resurrect the encrypted field, or a stale/revoked
        model credential could bypass the vault lifecycle (ADR-0033). Fail-closed."""
        server = create_test_virtualmin_server(api_username="fallback_user", _password="fallback_pass")
        gateway = self._make_gateway(server)

        for vault_err in ("Vault unavailable", "Credential expired 3 days ago", "Access denied to credential"):
            with self.subTest(vault_err=vault_err):
                mock_vault = MagicMock()
                mock_vault.get_credential.return_value = Err(vault_err)
                with patch.object(gateway, "_get_credential_vault", return_value=mock_vault):
                    result = gateway._get_credentials()
                self.assertTrue(result.is_err(), f"{vault_err!r} must be terminal, not fall back to the field")

    def test_vault_not_found_message_matches_resolver_sentinel(self):
        """CANARY (structural coupling): resolve_server_credentials permits the encrypted-field
        fallback ONLY when the vault error starts with _VAULT_NOT_FOUND_PREFIX. If CredentialVault's
        real not-found message ever drifts from that prefix, manual-server field fallback silently
        breaks. This locks the coupling to the REAL vault message so a drift fails loudly here — the
        other tests hardcode the message and would not catch it."""
        from apps.provisioning.virtualmin_gateway import _VAULT_NOT_FOUND_PREFIX  # noqa: PLC0415  # local: canary

        result = CredentialVault().get_credential(
            service_type="virtualmin", service_identifier="no-such-host.example.com", reason="sentinel canary"
        )

        self.assertTrue(result.is_err())
        self.assertTrue(
            result.unwrap_err().startswith(_VAULT_NOT_FOUND_PREFIX),
            f"vault not-found message {result.unwrap_err()!r} no longer starts with the resolver "
            f"sentinel {_VAULT_NOT_FOUND_PREFIX!r} — manual-server field fallback will break",
        )


class GatewayHttpAuthVaultFirstTest(TestCase):
    """#348 / ADR-0033: the gateway HTTP auth path (_execute_http_request) must resolve the
    Virtualmin credential vault-first — VirtualMin server creds live in the CredentialVault —
    never the (now-empty) encrypted_api_password field. Mocks ONLY the network + the vault so a
    real gateway call flows through the real auth construction."""

    def _vault_backed_server(self) -> VirtualminServer:
        return VirtualminServer.objects.create(
            name="vmin-vault-node",
            hostname="vmin-vault.example.com",
            api_port=10000,
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="ab" * 32,
            status="active",
            api_username="praho-api",
            encrypted_api_password=b"",  # the real secret lives in the vault
            max_domains=50,
            max_bandwidth_gb=1000,
        )

    @staticmethod
    def _ok_info_response() -> MagicMock:
        resp = MagicMock()
        resp.text = '{"status": "success", "data": {"version": "7.20"}}'
        resp.status_code = 200
        resp.headers = {}
        return resp

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_http_auth_uses_vault_credential(self, mock_get_vault, mock_safe_request):
        """DISCRIMINATOR: a normal gateway call authenticates with the vault credential, not b''."""
        server = self._vault_backed_server()
        vault = MagicMock()
        vault.get_credential.return_value = Ok(("praho-api", "vault-pw", {}))
        mock_get_vault.return_value = vault
        mock_safe_request.return_value = self._ok_info_response()

        result = VirtualminGateway(VirtualminConfig(server=server)).call("info")

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        _args, kwargs = mock_safe_request.call_args
        self.assertEqual(kwargs["auth"], ("praho-api", "vault-pw"))

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_http_auth_fails_closed_without_any_credential(self, mock_get_vault, mock_safe_request):
        """DISCRIMINATOR + security: empty field + vault miss → Err before the network. The gateway
        must never send an empty-password request (which would 401 and, via the auth manager,
        escalate toward master credentials)."""
        server = self._vault_backed_server()
        vault = MagicMock()
        vault.get_credential.return_value = Err("credential not found")
        mock_get_vault.return_value = vault

        result = VirtualminGateway(VirtualminConfig(server=server)).call("info")

        self.assertTrue(result.is_err())
        self.assertFalse(mock_safe_request.called, "must not send an empty-credential request")

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_from_credentials_direct_password_never_consults_vault(self, mock_get_vault, mock_safe_request):
        """GUARD: use_credential_vault=False (from_credentials — used by the verify_and_activate probe
        AND by _execute_master_proxy) must use the DIRECT password and NOT touch the vault. Otherwise
        master-proxy escalation would silently authenticate with the ACL vault credential instead of
        the configured master password."""
        mock_safe_request.return_value = self._ok_info_response()
        config = VirtualminConfig.from_credentials(
            hostname="vmin-direct.example.com",
            username="master-admin",
            password="master-pw",
            cert_fingerprint="ab" * 32,
            verify_ssl=False,
        )

        result = VirtualminGateway(config).call("info")

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        mock_get_vault.assert_not_called()
        _args, kwargs = mock_safe_request.call_args
        self.assertEqual(kwargs["auth"], ("master-admin", "master-pw"))

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_connection_test_uses_posted_credentials_not_vault(self, mock_get_vault, mock_safe_request):
        """Warning 2: the staff 'test these credentials' flow must probe the OPERATOR-ENTERED
        password (use_credential_vault=False), NOT the vault entry for that hostname — otherwise
        testing an existing host would silently authenticate with the stored vault credential and
        report a misleading result."""
        # A vault entry EXISTS for this hostname and would win if the flow were vault-first.
        vault = MagicMock()
        vault.get_credential.return_value = Ok(("vault-user", "vault-pw", {}))
        mock_get_vault.return_value = vault
        mock_safe_request.return_value = self._ok_info_response()

        temp_server = VirtualminServer(
            hostname="existing-host.example.com",
            api_port=10000,
            api_username="posted-user",
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="ab" * 32,
            status="active",
        )
        temp_server.set_api_password("posted-pw")

        from apps.provisioning.virtualmin_service import (  # noqa: PLC0415  # local: test-only path
            VirtualminProvisioningService,
        )

        result = VirtualminProvisioningService().test_server_connection(temp_server, use_credential_vault=False)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        _args, kwargs = mock_safe_request.call_args
        self.assertEqual(
            kwargs["auth"],
            ("posted-user", "posted-pw"),
            "connection test must use the operator-entered credentials, not the vault entry",
        )

    def test_vault_write_key_and_resolver_read_key_resolve_the_same_row(self):
        """Round-trip (write/read key coupling, Med 2): a credential stored under
        service_identifier=hostname — the key register_node writes (service_identifier=server.hostname)
        — must be readable by the production resolver, which reads by server.hostname. Proves the
        write key and the read key resolve the SAME vault row through the REAL vault (no mock)."""
        hostname = "roundtrip-node.example.com"
        CredentialVault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=hostname,
                username="praho-api",
                password="stored-pw",
            )
        )
        # A deploy-path server: empty encrypted field, hostname is the ONLY link to the vault row.
        server = VirtualminServer(hostname=hostname, api_username="field-user-ignored", status="active")

        result = resolve_server_credentials(server, vault=CredentialVault(), reason="round-trip test")

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(result.unwrap(), ("praho-api", "stored-pw"))


class VirtualminServerTLSFormTest(TestCase):
    """The staff form must not persist credential-bearing insecure transports."""

    def _data(self, **overrides: object) -> dict[str, object]:
        data: dict[str, object] = {
            "name": "secure-vmin",
            "hostname": "vmin.example.com",
            "api_port": 10000,
            "api_username": "praho_api",
            "api_password": "StrongPassword1!",
            "use_ssl": "on",
            "ssl_verify": "on",
            "ssl_cert_fingerprint": "",
            "status": "active",
            "max_domains": 100,
            "max_disk_gb": "",
            "max_bandwidth_gb": "",
        }
        data.update(overrides)
        return data

    def test_plain_http_configuration_is_rejected(self) -> None:
        form = VirtualminServerForm(data=self._data(use_ssl=""))

        self.assertFalse(form.is_valid())
        self.assertIn("use_ssl", form.errors)

    def test_disabling_ca_verification_requires_valid_sha256_pin(self) -> None:
        form = VirtualminServerForm(data=self._data(ssl_verify="", ssl_cert_fingerprint=""))

        self.assertFalse(form.is_valid())
        self.assertIn("ssl_cert_fingerprint", form.errors)

    def test_valid_sha256_pin_allows_private_ca_configuration(self) -> None:
        form = VirtualminServerForm(data=self._data(ssl_verify="", ssl_cert_fingerprint="sha256:" + "ab" * 32))

        self.assertTrue(form.is_valid(), form.errors.as_json())


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
