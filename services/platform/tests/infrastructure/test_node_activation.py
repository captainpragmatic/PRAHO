"""
#347 GAP 2 — the verify-and-activate bridge.

A node is registered `disabled` after deploy. `verify_and_activate` performs a
real credential handshake (gateway.test_connection) against the just-provisioned
API user and transitions the server `disabled -> active` ONLY on affirmative
health — never activating a server PRAHO cannot actually authenticate to.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_models import VirtualminServer


class VerifyAndActivateTests(TestCase):
    def _disabled_server(self) -> VirtualminServer:
        return VirtualminServer.objects.create(
            name="Node: prd-sha-tst-de-tst1-001",
            hostname="prd-sha-tst-de-tst1-001.example.com",
            api_port=10000,
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="ab" * 32,
            status="disabled",
            api_username="praho-api",
            encrypted_api_password=b"",
            max_domains=50,
            max_bandwidth_gb=1000,
        )

    @staticmethod
    def _mock_vault(mock_get_vault):
        """A present vault credential so the flow reaches the gateway decision logic
        (verify_and_activate now fetches the vault credential first)."""
        mock_get_vault.return_value.get_credential.return_value = Ok(("praho-api", "vault-pw", {}))

    @patch("apps.common.credential_vault.get_credential_vault")
    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_activates_when_credential_handshake_is_healthy(self, mock_gateway_cls, mock_get_vault):
        server = self._disabled_server()
        self._mock_vault(mock_get_vault)
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": True})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        server.refresh_from_db()
        self.assertEqual(server.status, "active")

    @patch("apps.common.credential_vault.get_credential_vault")
    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_stays_disabled_when_handshake_errs(self, mock_gateway_cls, mock_get_vault):
        server = self._disabled_server()
        self._mock_vault(mock_get_vault)
        mock_gateway_cls.return_value.test_connection.return_value = Err("401 unauthorized")

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")

    @patch("apps.common.credential_vault.get_credential_vault")
    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_stays_disabled_when_health_not_affirmative(self, mock_gateway_cls, mock_get_vault):
        """A missing/non-True 'healthy' is not proof — do not activate (#325 posture)."""
        server = self._disabled_server()
        self._mock_vault(mock_get_vault)
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": "maybe"})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")

    @patch("apps.common.credential_vault.get_credential_vault")
    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_only_activates_a_disabled_server(self, mock_gateway_cls, mock_get_vault):
        """CAS guard: never flip a server that has since left 'disabled'."""
        server = self._disabled_server()
        self._mock_vault(mock_get_vault)
        VirtualminServer.objects.filter(pk=server.pk).update(status="failed")
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": True})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "failed")


class VerifyAndActivateRealHandshakeTests(TestCase):
    """#348 discriminators: exercise the REAL gateway health gate + auth path, mocking
    ONLY the network (safe_request) and the vault. The original tests above mock
    VirtualminGateway.test_connection, which hides two production defects:

      P1a: a freshly-registered server is status='disabled', but the real
           VirtualminGateway._validate_server_health rejects any non-active server's
           'info' call (the failed_by_health_check sweep exception does not apply to a
           fresh registration) — so the probe can never run and the node never activates.
      P1b: register_node stores the credential in the vault and sets
           encrypted_api_password=b'', but the HTTP auth uses server.get_api_password()
           (empty) — so even if the probe ran it would send no password.

    These tests flow a disabled node through the real gate + real auth construction, so
    they FAIL against the pre-fix code and PASS after verify_and_activate uses
    VirtualminConfig.from_credentials (active-status probe) with the vault credential.
    """

    def _disabled_server(self) -> VirtualminServer:
        return VirtualminServer.objects.create(
            name="Node: prd-sha-tst-de-tst1-002",
            hostname="prd-sha-tst-de-tst1-002.example.com",
            api_port=10000,
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="ab" * 32,
            status="disabled",
            api_username="praho-api",
            encrypted_api_password=b"",  # the real secret lives in the vault
            max_domains=50,
            max_bandwidth_gb=1000,
        )

    @staticmethod
    def _vault(username: str = "praho-api", password: str = "s3cr3t-vault-pw") -> MagicMock:  # noqa: S107  # test fixture, not a real secret
        vault = MagicMock()
        vault.get_credential.return_value = Ok((username, password, {}))
        return vault

    @staticmethod
    def _ok_info_response() -> MagicMock:
        resp = MagicMock()
        resp.text = '{"status": "success", "data": {"version": "7.20"}}'
        resp.status_code = 200
        resp.headers = {}
        return resp

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_disabled_node_activates_through_real_health_gate_with_vault_credential(
        self, mock_get_vault, mock_safe_request
    ):
        """P1a + P1b discriminator: a disabled node with a valid vault credential must
        activate, flowing through the REAL _validate_server_health and REAL auth
        construction (only the network is mocked)."""
        server = self._disabled_server()
        mock_get_vault.return_value = self._vault(password="s3cr3t-vault-pw")
        mock_safe_request.return_value = self._ok_info_response()

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        server.refresh_from_db()
        self.assertEqual(server.status, "active")
        # P1b: the probe must authenticate with the VAULT credential, not the empty
        # encrypted_api_password. Assert the actual network call carried it.
        self.assertTrue(mock_safe_request.called, "the probe never reached the network (health gate rejected it?)")
        _args, kwargs = mock_safe_request.call_args
        self.assertEqual(kwargs["auth"], ("praho-api", "s3cr3t-vault-pw"))

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_vault_miss_leaves_node_disabled(self, mock_get_vault, mock_safe_request):
        """Fail-safe: no vault credential (e.g. register_node's vault store failed, which
        it tolerates) → never activate, never even hit the network."""
        server = self._disabled_server()
        vault = MagicMock()
        vault.get_credential.return_value = Err("credential not found")
        mock_get_vault.return_value = vault

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")
        self.assertFalse(mock_safe_request.called)

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_bad_credential_handshake_leaves_node_disabled(self, mock_get_vault, mock_safe_request):
        """Fail-safe: the node rejects the credential (real auth path, non-success info
        response) → stays disabled, never customer-routed."""
        server = self._disabled_server()
        mock_get_vault.return_value = self._vault()
        resp = MagicMock()
        resp.text = '{"status": "failure", "error": "Invalid login"}'
        resp.status_code = 401
        resp.headers = {}
        mock_safe_request.return_value = resp

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")
