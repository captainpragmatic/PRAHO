"""Regression tests for trusted Virtualmin certificate pin registration."""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.registration_service import NodeRegistrationService


class NodeRegistrationTLSPinTests(TestCase):
    """Auto-registered self-signed nodes must remain reachable without trusting TOFU."""

    def _deployment(self) -> MagicMock:
        deployment = MagicMock()
        deployment.status = "registering"
        deployment.ipv4_address = "203.0.113.10"
        deployment.virtualmin_server = None
        deployment.hostname = "prd-sha-tst-de-tst1-001"
        deployment.fqdn = "prd-sha-tst-de-tst1-001.example.com"
        deployment.id = 1
        deployment.node_size.max_domains = 50
        deployment.node_size.max_bandwidth_gb = 1000
        return deployment

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_persists_certificate_pin_read_over_trusted_ssh(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        fingerprint = "ab" * 32
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok(fingerprint)
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_server_model.objects.create.return_value = MagicMock(id=7)

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(
            mock_server_model.objects.create.call_args.kwargs["ssl_cert_fingerprint"],
            fingerprint,
        )

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_fails_closed_when_certificate_pin_cannot_be_verified(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Err("SSH trust failed")

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_err())
        self.assertIn("certificate fingerprint", result.unwrap_err())
        mock_server_model.objects.create.assert_not_called()

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_creates_disabled_server_until_credentials_configured(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        """#328-4: the admin password is generated + vaulted but never configured
        on the node, so the server must NOT be registered 'active' (which would
        make _select_best_server place domains on it and fail auth). It is
        'disabled' until an operator configures and verifies the credentials."""
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok("cd" * 32)
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_server_model.objects.create.return_value = MagicMock(id=9)

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(mock_server_model.objects.create.call_args.kwargs["status"], "disabled")


class VirtualminCertificatePinCommandTests(TestCase):
    """Existing self-signed node records have an explicit trusted migration path."""

    @patch("apps.infrastructure.management.commands.pin_virtualmin_certificates.get_validation_service")
    @patch("apps.infrastructure.management.commands.pin_virtualmin_certificates.VirtualminServer.objects.filter")
    def test_command_pins_existing_server_from_trusted_deployment(
        self,
        mock_filter: MagicMock,
        mock_get_validation: MagicMock,
    ) -> None:
        server = MagicMock(id=7, hostname="node.example.com", node_deployment=MagicMock())
        mock_filter.return_value = [server]
        fingerprint = "cd" * 32
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok(fingerprint)
        stdout = StringIO()

        call_command("pin_virtualmin_certificates", stdout=stdout)

        self.assertEqual(server.ssl_cert_fingerprint, fingerprint)
        server.save.assert_called_once_with(update_fields=["ssl_cert_fingerprint", "updated_at"])
        self.assertIn("Pinned 1 Virtualmin certificate", stdout.getvalue())
