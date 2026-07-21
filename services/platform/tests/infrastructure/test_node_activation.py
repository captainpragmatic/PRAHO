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
    def test_activation_is_total_returns_err_on_db_error(self, mock_get_vault, mock_safe_request):
        """#348 #7: a transient DB error during the CAS update (previously OUTSIDE the try) must
        surface as Err — the node stays disabled (fail-safe) — never propagate as an exception that
        would crash the caller's deployment."""
        from django.db import OperationalError  # noqa: PLC0415  # local: test-only

        server = self._disabled_server()
        mock_get_vault.return_value = self._vault()
        mock_safe_request.return_value = self._ok_info_response()

        with patch.object(VirtualminServer.objects, "filter", side_effect=OperationalError("connection lost")):
            result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err(), "a DB error in the CAS must be caught and returned as Err")
        self.assertIn("raised", result.unwrap_err())

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

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    @patch("apps.common.credential_vault.get_credential_vault")
    def test_activated_node_provisions_with_vault_credential(self, mock_get_vault, mock_safe_request):
        """#1 KILL-SHOT: the activation guarantee must transfer to PRODUCTION provisioning.

        After verify_and_activate flips the node to active, a NORMAL provisioning gateway
        — VirtualminConfig(server=server), the path every create-domain/backup/DR call uses,
        NOT from_credentials — must authenticate with the VAULT credential. Pre-fix this FAILS:
        the normal path reads server.get_api_password() which decrypts encrypted_api_password=b''
        to '' and sends empty auth (active node, unusable credential — Codex #1). Post-fix the
        gateway resolves the credential vault-first, so the wire carries the vault username/password.
        """
        server = self._disabled_server()  # encrypted_api_password=b"" — the real secret is in the vault
        mock_get_vault.return_value = self._vault(username="praho-api", password="s3cr3t-vault-pw")
        mock_safe_request.return_value = self._ok_info_response()

        activate = NodeRegistrationService().verify_and_activate(server)
        self.assertTrue(activate.is_ok(), activate.unwrap_err() if activate.is_err() else "")
        server.refresh_from_db()
        self.assertEqual(server.status, "active")

        # PRODUCTION path: build a normal gateway from the persisted server row (not from_credentials).
        from apps.provisioning.virtualmin_gateway import (  # noqa: PLC0415  # local: test-only path
            VirtualminConfig,
            VirtualminGateway,
        )

        mock_safe_request.reset_mock()
        result = VirtualminGateway(VirtualminConfig(server=server)).call("info")

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertTrue(mock_safe_request.called, "normal provisioning never reached the network")
        _args, kwargs = mock_safe_request.call_args
        self.assertEqual(
            kwargs["auth"],
            ("praho-api", "s3cr3t-vault-pw"),
            "production provisioning must authenticate with the vault credential, not the empty field",
        )
