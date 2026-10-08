"""Coverage additions for authentication-health command output through real auth paths."""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch
from uuid import uuid4

import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_credentials import create_test_virtualmin_server


@override_settings(
    VIRTUALMIN_MASTER_USERNAME=None,
    VIRTUALMIN_MASTER_PASSWORD=None,
    VIRTUALMIN_SSH_PRIVATE_KEY_PATH=None,
    VIRTUALMIN_SSH_PASSWORD=None,
)
class AuthHealthCommandCoverageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.server = create_test_virtualmin_server(
            name="auth-coverage", hostname="auth-coverage.example.test", status="active"
        )
        ssh = patch("apps.provisioning.virtualmin_auth_manager.paramiko.SSHClient", autospec=True)
        self.ssh_factory = ssh.start()
        self.addCleanup(ssh.stop)

    def command(self, *arguments: str) -> str:
        output = io.StringIO()
        call_command("test_virtualmin_auth_health", *arguments, stdout=output, no_color=True)
        return output.getvalue()

    def test_missing_server_raises_an_actionable_command_error(self) -> None:
        with self.assertRaisesRegex(CommandError, "not found"):
            self.command("--server-id", str(uuid4()))

    def test_single_server_renders_acl_success_and_filters_requested_method(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "success"}),
        ):
            output = self.command("--server-id", str(self.server.pk), "--method", "acl")
        self.assertIn(self.server.hostname, output)
        self.assertIn("acl: Working", output)
        self.assertIn(f"API Port: {self.server.api_port}", output)
        self.assertNotIn("master_proxy:", output)
        self.assertNotIn("ssh_sudo:", output)

    def test_single_server_reports_complete_failure_without_fallback_credentials(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, 403)):
            output = self.command("--server-id", str(self.server.pk))
        self.assertIn("acl: Access forbidden", output)
        self.assertIn("master_proxy: Master admin credentials not configured", output)
        self.assertIn("ssh_sudo:", output)
        self.assertIn("CRITICAL: No authentication methods working", output)

    @override_settings(VIRTUALMIN_SSH_PASSWORD="health-test-password")
    def test_ssh_fallback_renders_working_method_and_acl_warning(self) -> None:
        sent: list[str] = []
        stdout = MagicMock()
        stdout.read.return_value = b"Domain listing completed successfully\n"
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""

        def execute(command: str, timeout: int) -> tuple[io.BytesIO, MagicMock, MagicMock]:
            sent.append(command)
            return io.BytesIO(), stdout, stderr

        self.ssh_factory.return_value.exec_command.side_effect = execute
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, 403)):
            output = self.command("--server-id", str(self.server.pk), "--method", "ssh_sudo")
        self.assertIn("ssh_sudo: Working", output)
        self.assertIn("ACL authentication failed - using fallback", output)
        self.assertNotIn("acl:", output)
        self.assertEqual(sent, ["sudo /usr/sbin/virtualmin list-domains --multiline"])

    @override_settings(VIRTUALMIN_MASTER_USERNAME="master-health", VIRTUALMIN_MASTER_PASSWORD="master-test-password")
    def test_master_fallback_is_reported_in_single_and_summary_modes(self) -> None:
        sent: list[object] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(kwargs["auth"])
            status = 200 if kwargs["auth"] == ("master-health", "master-test-password") else 403
            return http_response({"status": "success"}, status)

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            single = self.command("--server-id", str(self.server.pk), "--method", "master_proxy")
            summary = self.command()
        self.assertIn("master_proxy: Working", single)
        self.assertIn("ACL authentication failed - using fallback", single)
        self.assertIn(("master-health", "master-test-password"), sent)
        self.assertIn("ACL failed: 1", summary)
        self.assertIn("Fallback available: 1", summary)
        self.assertNotIn("Complete failures:", summary)

    def test_all_server_summary_reports_acl_health_and_complete_failures(self) -> None:
        create_test_virtualmin_server(name="auth-failed", hostname="auth-failed.example.test", status="active")
        create_test_virtualmin_server(name="auth-inactive", hostname="auth-inactive.example.test", status="maintenance")

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            status = 403 if "auth-failed." in url else 200
            return http_response({"status": "success"}, status)

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            output = self.command()
        self.assertIn("Overall ACL Health: 50.0%", output)
        self.assertIn("Servers tested: 2", output)
        self.assertIn("ACL working: 1", output)
        self.assertIn("ACL failed: 1", output)
        self.assertIn("Complete failures: 1", output)
        self.assertIn("ACL AUTHENTICATION RISK DETECTED", output)
        self.assertIn("Server: auth-failed.example.test", output)
        self.assertNotIn("auth-inactive.example.test", output)

    def test_summary_warning_threshold_and_healthy_threshold(self) -> None:
        for index in range(3):
            create_test_virtualmin_server(name=f"auth-{index}", hostname=f"auth-{index}.example.test", status="active")

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            status = 403 if "auth-0." in url else 200
            return http_response({"status": "success"}, status)

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            warning = self.command()
        self.assertIn("⚠️ Overall ACL Health: 75.0%", warning)
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "success"}),
        ):
            healthy = self.command()
        self.assertIn("✅ Overall ACL Health: 100.0%", healthy)
        self.assertNotIn("ACL AUTHENTICATION RISK DETECTED", healthy)

    def test_server_removed_during_probe_is_reported_without_aborting_summary(self) -> None:
        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            VirtualminServer.objects.filter(pk=self.server.pk).delete()
            return http_response({}, 403)

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            output = self.command()
        self.assertIn("Servers tested: 1", output)
        self.assertIn(f"Server {self.server.pk} not found in database", output)
        self.assertFalse(VirtualminServer.objects.filter(pk=self.server.pk).exists())

    def test_empty_active_inventory_reports_zero_without_division_error(self) -> None:
        self.server.status = "maintenance"
        self.server.save(update_fields=["status"])
        output = self.command()
        self.assertIn("Overall ACL Health: 0.0%", output)
        self.assertIn("Servers tested: 0", output)
        self.assertNotIn("📊 Server:", output)
