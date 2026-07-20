"""
#347 GAP 2 — the verify-and-activate bridge.

A node is registered `disabled` after deploy. `verify_and_activate` performs a
real credential handshake (gateway.test_connection) against the just-provisioned
API user and transitions the server `disabled -> active` ONLY on affirmative
health — never activating a server PRAHO cannot actually authenticate to.
"""

from __future__ import annotations

from unittest.mock import patch

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

    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_activates_when_credential_handshake_is_healthy(self, mock_gateway_cls):
        server = self._disabled_server()
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": True})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        server.refresh_from_db()
        self.assertEqual(server.status, "active")

    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_stays_disabled_when_handshake_errs(self, mock_gateway_cls):
        server = self._disabled_server()
        mock_gateway_cls.return_value.test_connection.return_value = Err("401 unauthorized")

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")

    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_stays_disabled_when_health_not_affirmative(self, mock_gateway_cls):
        """A missing/non-True 'healthy' is not proof — do not activate (#325 posture)."""
        server = self._disabled_server()
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": "maybe"})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")

    @patch("apps.provisioning.virtualmin_gateway.VirtualminGateway")
    def test_only_activates_a_disabled_server(self, mock_gateway_cls):
        """CAS guard: never flip a server that has since left 'disabled'."""
        server = self._disabled_server()
        VirtualminServer.objects.filter(pk=server.pk).update(status="failed")
        mock_gateway_cls.return_value.test_connection.return_value = Ok({"healthy": True})

        result = NodeRegistrationService().verify_and_activate(server)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "failed")
