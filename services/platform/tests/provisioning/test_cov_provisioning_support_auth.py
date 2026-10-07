"""Coverage additions for authentication transport outcomes and the health command."""

from __future__ import annotations

import shlex
from io import StringIO
from typing import cast
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit
from uuid import uuid4

import paramiko
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from requests import Response

from apps.common.types import Retriability
from apps.provisioning.virtualmin_auth_manager import (
    CACHE_AUTH_HEALTH_PREFIX,
    CACHE_AUTH_METHOD_PREFIX,
    AuthMethod,
    VirtualminAuthenticationManager,
)
from apps.provisioning.virtualmin_auth_manager import test_acl_authentication_health as authentication_health
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "wp17-support-auth"}},
    VIRTUALMIN_MASTER_USERNAME=None,
    VIRTUALMIN_MASTER_PASSWORD=None,
    VIRTUALMIN_SSH_USERNAME="support-ssh",
    VIRTUALMIN_SSH_PASSWORD="support-ssh-password",
    VIRTUALMIN_SSH_PRIVATE_KEY_PATH=None,
    PRAHO_SSH_KNOWN_HOSTS_PATH="",
)
class ProvisioningAuthenticationTests(VirtualminViewsFixture):
    def setUp(self) -> None:
        cache.clear()
        super().setUp()
        self.addCleanup(cache.clear)
        self.statuses: dict[tuple[str, str], int] = {}
        self.ssh = MagicMock(spec=paramiko.SSHClient)
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.stdout.read.return_value = b"Domain created successfully\n"
        self.stderr.read.return_value = b""
        self.stdout.channel.recv_exit_status.return_value = 0
        self.ssh.exec_command.return_value = (MagicMock(), self.stdout, self.stderr)
        transport = patch("apps.provisioning.virtualmin_auth_manager.paramiko.SSHClient", return_value=self.ssh)
        transport.start()
        self.addCleanup(transport.stop)

    def respond(self, method: str, url: str, **kwargs: object) -> Response:
        response = super().respond(method, url, **kwargs)
        auth = cast("tuple[str, str]", kwargs["auth"])
        response.status_code = self.statuses.get((str(urlsplit(url).hostname), auth[0]), self.http_status)
        return response

    def test_invalid_program_is_rejected_before_any_transport(self) -> None:
        result = VirtualminAuthenticationManager(self.server).execute_virtualmin_command("invalid-program", {})
        self.assertTrue(result.is_err())
        self.assertIn("Virtualmin command validation failed", result.unwrap_err())
        self.assertEqual(self.requests, [])

    def test_ssh_private_key_builds_quoted_cli_and_caches_success(self) -> None:
        key = f"{CACHE_AUTH_METHOD_PREFIX}{self.server.pk}"
        failure_key = f"{CACHE_AUTH_HEALTH_PREFIX}{self.server.pk}_ssh_sudo"
        cache.set(failure_key, "previous failure")
        with (
            self.settings(VIRTUALMIN_SSH_PRIVATE_KEY_PATH="/coverage/key"),
            VirtualminAuthenticationManager(self.server) as manager,
        ):
            result = manager.execute_virtualmin_command(
                "create-domain",
                {"domain": "tenant.example.com", "desc": "Tenant hosting", "web": True, "mail": False, "dns": None},
                force_method=AuthMethod.SSH_SUDO,
            )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), {"success": True, "message": "Domain created successfully"})
        command = self.ssh.exec_command.call_args.args[0]
        self.assertEqual(
            shlex.split(command),
            [
                "sudo",
                "/usr/sbin/virtualmin",
                "create-domain",
                "--domain",
                "tenant.example.com",
                "--desc",
                "Tenant hosting",
                "--web",
            ],
        )
        self.assertEqual(self.ssh.connect.call_args.kwargs["key_filename"], "/coverage/key")
        self.assertIsInstance(self.ssh.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
        self.assertEqual(cache.get(key), "ssh_sudo")
        self.assertIsNone(cache.get(failure_key))
        self.assertIsNone(manager._ssh_client)

    def test_ssh_password_and_plain_output_return_success(self) -> None:
        self.stdout.read.return_value = b"tenant.example.com\n"
        with VirtualminAuthenticationManager(self.server) as manager:
            result = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.SSH_SUDO)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), {"success": True, "message": "tenant.example.com"})
        self.assertEqual(self.ssh.connect.call_args.kwargs["password"], "support-ssh-password")
        self.assertNotIn("key_filename", self.ssh.connect.call_args.kwargs)

    def test_ssh_exit_failure_and_cli_failure_return_errors(self) -> None:
        cases = (
            (2, b"", b"permission denied", "Command failed (exit 2)"),
            (0, b"FAILED: remote error", b"", "CLI command failed"),
        )
        for exit_code, stdout, stderr, error in cases:
            self.stdout.channel.recv_exit_status.return_value = exit_code
            self.stdout.read.return_value = stdout
            self.stderr.read.return_value = stderr
            with self.subTest(exit_code=exit_code), VirtualminAuthenticationManager(self.server) as manager:
                result = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.SSH_SUDO)
                self.assertTrue(result.is_err())
                self.assertIn(error, result.unwrap_err())
                self.assertIn(error, cache.get(f"{CACHE_AUTH_HEALTH_PREFIX}{self.server.pk}_ssh_sudo"))

    def test_ssh_transport_exception_disconnects_and_returns_an_error(self) -> None:
        self.ssh.exec_command.side_effect = OSError("channel closed")
        manager = VirtualminAuthenticationManager(self.server)
        result = manager.execute_virtualmin_command("create-domain", {}, force_method=AuthMethod.SSH_SUDO)
        self.assertTrue(result.is_err())
        self.assertIn("SSH command execution failed: channel closed", result.unwrap_err())
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        self.assertIsNone(manager._ssh_client)

    def test_missing_ssh_credentials_fail_without_caching_success(self) -> None:
        with self.settings(VIRTUALMIN_SSH_PASSWORD=None):
            manager = VirtualminAuthenticationManager(self.server)
            result = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.SSH_SUDO)
        self.assertTrue(result.is_err())
        self.assertIn("No SSH credentials configured", result.unwrap_err())
        self.assertIsNone(manager._ssh_client)
        self.assertIsNone(cache.get(f"{CACHE_AUTH_METHOD_PREFIX}{self.server.pk}"))

    @override_settings(VIRTUALMIN_MASTER_USERNAME="master-user", VIRTUALMIN_MASTER_PASSWORD="master-password")
    def test_master_proxy_preserves_success_credentials_and_rate_limit(self) -> None:
        manager = VirtualminAuthenticationManager(self.server)
        result = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.MASTER_PROXY)
        self.assertTrue(result.is_ok(), result)
        self.assertTrue(result.unwrap().success)
        self.assertEqual(self.requests[-1]["auth"], ("master-user", "master-password"))
        self.http_status = 429
        with patch("apps.provisioning.virtualmin_gateway.time.sleep"):
            failed = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.MASTER_PROXY)
        self.assertTrue(failed.is_err())
        self.assertEqual(failed.retriability, Retriability.RETRIABLE)
        self.assertIn("Server rate limit exceeded", failed.unwrap_err())

    def test_health_summary_distinguishes_acl_fallback_and_complete_failure(self) -> None:
        for name in ("fallback", "failed"):
            server = VirtualminServer.objects.create(
                name=name, hostname=f"{name}.example.com", api_username="praho-acl"
            )
            server.set_api_password("support-password")
            server.save(update_fields=["encrypted_api_password"])
            self.statuses[(server.hostname, "praho-acl")] = 401
        VirtualminServer.objects.create(name="disabled", hostname="disabled.example.com", status="disabled")
        connected: list[str] = []

        def connect(**kwargs: object) -> None:
            connected.append(str(kwargs["hostname"]))

        def execute(command: str, **kwargs: object) -> tuple[MagicMock, MagicMock, MagicMock]:
            failed = connected[-1] == "failed.example.com"
            self.stdout.channel.recv_exit_status.return_value = 1 if failed else 0
            self.stderr.read.return_value = b"denied" if failed else b""
            return MagicMock(), self.stdout, self.stderr

        self.ssh.connect.side_effect = connect
        self.ssh.exec_command.side_effect = execute
        summary = authentication_health()
        self.assertEqual(
            {
                key: summary[key]
                for key in ("servers_tested", "acl_working", "acl_failed", "fallback_working", "completely_failed")
            },
            {"servers_tested": 3, "acl_working": 1, "acl_failed": 2, "fallback_working": 1, "completely_failed": 1},
        )
        details = {row["hostname"]: row["status"] for row in summary["server_details"]}
        self.assertEqual(
            details,
            {
                self.server.hostname: "acl_healthy",
                "fallback.example.com": "fallback_available",
                "failed.example.com": "all_failed",
            },
        )

    def test_health_command_filters_display_and_reports_missing_server(self) -> None:
        output = StringIO()
        call_command(
            "test_virtualmin_auth_health", "--server-id", str(self.server.pk), "--method", "acl", stdout=output
        )
        self.assertIn(self.server.hostname, output.getvalue())
        self.assertIn("acl: Working", output.getvalue())
        self.assertNotIn("ssh_sudo: Working", output.getvalue())
        self.assertNotIn("master_proxy:", output.getvalue())
        with self.assertRaisesMessage(CommandError, "not found"):
            call_command("test_virtualmin_auth_health", "--server-id", str(uuid4()), stdout=StringIO())

    def test_all_server_health_command_reports_acl_failure_and_fallback(self) -> None:
        self.http_status = 401
        output = StringIO()
        call_command("test_virtualmin_auth_health", "--fix-failures", stdout=output)
        self.assertIn("Servers tested: 1", output.getvalue())
        self.assertIn("ACL failed: 1", output.getvalue())
        self.assertIn("Fallback available: 1", output.getvalue())
        self.assertIn("ACL AUTHENTICATION RISK DETECTED", output.getvalue())
        self.assertIn(self.server.hostname, output.getvalue())

    def test_disconnect_tolerates_transport_close_error(self) -> None:
        self.ssh.close.side_effect = OSError("already disconnected")
        with VirtualminAuthenticationManager(self.server) as manager:
            result = manager.execute_virtualmin_command("list-domains", {}, force_method=AuthMethod.SSH_SUDO)
        self.assertTrue(result.is_ok(), result)
        self.assertIsNone(manager._ssh_client)
