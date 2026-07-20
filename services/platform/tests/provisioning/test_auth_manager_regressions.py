"""
Tests for VirtualminAuthenticationManager audit fixes.

Covers:
- H16: _execute_with_method must handle unknown AuthMethod values
- Existing method dispatch verification (ACL, MASTER_PROXY, SSH_SUDO)
"""

from __future__ import annotations

from enum import Enum
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok, Retriability
from apps.provisioning.virtualmin_auth_manager import (
    AuthMethod,
    VirtualminAuthenticationManager,
)


class ExecuteWithMethodDispatchTests(TestCase):
    """H16: _execute_with_method must return Err for unknown auth methods."""

    def setUp(self) -> None:
        self.mock_server = MagicMock()
        self.mock_server.hostname = "test.example.com"
        self.mock_server.id = 1
        self.manager = VirtualminAuthenticationManager(self.mock_server)

    def test_execute_with_method_unknown_returns_err(self) -> None:
        """Unknown AuthMethod values must return Err, not fall through to None."""

        # Create a mock enum value that isn't ACL, MASTER_PROXY, or SSH_SUDO
        class FakeAuthMethod(Enum):
            UNKNOWN = "unknown_method"

        # Monkey-patch to test the else branch
        fake_method = MagicMock()
        fake_method.value = "unknown_method"
        fake_method.__eq__ = lambda self, other: False  # Won't match any known method

        result = self.manager._execute_with_method(fake_method, "list-domains", {})

        self.assertTrue(result.is_err())
        self.assertIn("Unknown auth method", result.unwrap_err())

    @patch.object(VirtualminAuthenticationManager, "_execute_acl_auth")
    def test_execute_with_method_acl(self, mock_acl: MagicMock) -> None:
        """ACL method dispatches to _execute_acl_auth."""
        expected = Ok({"domains": []})
        mock_acl.return_value = expected

        result = self.manager._execute_with_method(AuthMethod.ACL, "list-domains", {"multiline": True})

        mock_acl.assert_called_once_with("list-domains", {"multiline": True})
        self.assertEqual(result, expected)

    @patch.object(VirtualminAuthenticationManager, "_execute_master_proxy")
    def test_execute_with_method_master_proxy(self, mock_proxy: MagicMock) -> None:
        """MASTER_PROXY method dispatches to _execute_master_proxy."""
        expected = Ok({"domains": []})
        mock_proxy.return_value = expected

        result = self.manager._execute_with_method(AuthMethod.MASTER_PROXY, "list-domains", {})

        mock_proxy.assert_called_once_with("list-domains", {})
        self.assertEqual(result, expected)

    @patch.object(VirtualminAuthenticationManager, "_execute_ssh_sudo")
    def test_execute_with_method_ssh_sudo(self, mock_ssh: MagicMock) -> None:
        """SSH_SUDO method dispatches to _execute_ssh_sudo."""
        expected = Ok({"success": True, "message": "done"})
        mock_ssh.return_value = expected

        result = self.manager._execute_with_method(AuthMethod.SSH_SUDO, "create-domain", {"domain": "test.com"})

        mock_ssh.assert_called_once_with("create-domain", {"domain": "test.com"})
        self.assertEqual(result, expected)

    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway")
    def test_acl_wrapper_preserves_gateway_retriability(self, gateway_cls: MagicMock) -> None:
        self.mock_server.api_username = "api"
        self.mock_server.api_port = 10000
        self.mock_server.use_ssl = True
        self.mock_server.ssl_verify = True
        self.mock_server.get_api_password.return_value = "secret"
        gateway_cls.return_value.call.return_value = Err(
            "rate limited", retriability=Retriability.RETRIABLE
        )

        result = self.manager._execute_acl_auth("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_auth_fallback_preserves_terminal_retriability(self) -> None:
        terminal = Err("bad credentials", retriability=Retriability.NOT_RETRIABLE)

        with (
            patch.object(self.manager, "_get_auth_method_priority", return_value=[AuthMethod.ACL]),
            patch.object(self.manager, "_execute_with_method", return_value=terminal),
            patch.object(self.manager, "_cache_failed_auth_method"),
        ):
            result = self.manager.execute_virtualmin_command("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)

    def test_auth_fallback_stops_after_ambiguous_outcome(self) -> None:
        ambiguous = Err("response lost", retriability=Retriability.UNKNOWN)

        with (
            patch.object(
                self.manager,
                "_get_auth_method_priority",
                return_value=[AuthMethod.ACL, AuthMethod.MASTER_PROXY],
            ),
            patch.object(
                self.manager,
                "_execute_with_method",
                side_effect=[ambiguous, Ok({"success": True})],
            ) as execute,
            patch.object(self.manager, "_cache_failed_auth_method"),
        ):
            result = self.manager.execute_virtualmin_command("create-domain", {"domain": "example.com"})

        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        execute.assert_called_once()

    def test_auth_fallback_allows_ambiguous_read_only_outcome(self) -> None:
        ambiguous = Err("response lost", retriability=Retriability.UNKNOWN)

        with (
            patch.object(
                self.manager,
                "_get_auth_method_priority",
                return_value=[AuthMethod.ACL, AuthMethod.MASTER_PROXY],
            ),
            patch.object(
                self.manager,
                "_execute_with_method",
                side_effect=[ambiguous, Ok({"domains": []})],
            ) as execute,
            patch.object(self.manager, "_cache_failed_auth_method"),
        ):
            result = self.manager.execute_virtualmin_command("list-domains", {})

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), {"domains": []})
        self.assertEqual(execute.call_count, 2)

    def test_auth_fallback_stops_after_unexpected_mutation_exception(self) -> None:
        with (
            patch.object(
                self.manager,
                "_get_auth_method_priority",
                return_value=[AuthMethod.ACL, AuthMethod.MASTER_PROXY],
            ),
            patch.object(
                self.manager,
                "_execute_with_method",
                side_effect=[RuntimeError("response lost"), Ok({"success": True})],
            ) as execute,
            patch.object(self.manager, "_cache_failed_auth_method"),
        ):
            result = self.manager.execute_virtualmin_command("modify-domain", {"domain": "example.com"})

        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        execute.assert_called_once()
