"""
Tests for VirtualminAuthenticationManager audit fixes.

Covers:
- H16: _execute_with_method must handle unknown AuthMethod values
- Existing method dispatch verification (ACL, MASTER_PROXY, SSH_SUDO)
"""

from __future__ import annotations

from enum import Enum
from unittest.mock import MagicMock, call, patch

import paramiko
from django.test import TestCase, override_settings

from apps.common.types import Err, Ok
from apps.provisioning.virtualmin_auth_manager import (
    AuthMethod,
    VirtualminAuthenticationManager,
)
from apps.provisioning.virtualmin_gateway import VirtualminAPIError, VirtualminAuthError


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

    @patch.object(VirtualminAuthenticationManager, "_cache_failed_auth_method")
    @patch.object(VirtualminAuthenticationManager, "_get_auth_method_priority")
    @patch.object(VirtualminAuthenticationManager, "_execute_with_method")
    def test_non_authentication_error_never_escalates_privileges(
        self,
        mock_execute: MagicMock,
        mock_priority: MagicMock,
        _mock_cache_failed: MagicMock,
    ) -> None:
        mock_priority.return_value = [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO]
        error = VirtualminAPIError("validation failed")
        mock_execute.return_value = Err(error)

        result = self.manager.execute_virtualmin_command("create-domain", {})

        self.assertTrue(result.is_err())
        mock_execute.assert_called_once_with(AuthMethod.ACL, "create-domain", {})

    @patch.object(VirtualminAuthenticationManager, "_cache_working_auth_method")
    @patch.object(VirtualminAuthenticationManager, "_cache_failed_auth_method")
    @patch.object(VirtualminAuthenticationManager, "_get_auth_method_priority")
    @patch.object(VirtualminAuthenticationManager, "_execute_with_method")
    def test_authentication_error_may_use_next_configured_method(
        self,
        mock_execute: MagicMock,
        mock_priority: MagicMock,
        _mock_cache_failed: MagicMock,
        _mock_cache_working: MagicMock,
    ) -> None:
        mock_priority.return_value = [AuthMethod.ACL, AuthMethod.MASTER_PROXY]
        mock_execute.side_effect = [Err(VirtualminAuthError("unauthorized")), Ok({"success": True})]

        result = self.manager.execute_virtualmin_command("list-domains", {})

        self.assertTrue(result.is_ok())
        self.assertEqual(
            mock_execute.call_args_list,
            [
                call(AuthMethod.ACL, "list-domains", {}),
                call(AuthMethod.MASTER_PROXY, "list-domains", {}),
            ],
        )

    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway.call")
    def test_acl_preserves_raised_typed_authentication_error(self, mock_call: MagicMock) -> None:
        mock_call.side_effect = VirtualminAuthError("unauthorized")

        result = self.manager._execute_acl_auth("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), VirtualminAuthError)

    @override_settings(VIRTUALMIN_SSH_PASSWORD="test-password")
    @patch("apps.provisioning.virtualmin_auth_manager.paramiko.SSHClient")
    def test_ssh_rejects_unknown_host_keys(self, mock_client_class: MagicMock) -> None:
        client = mock_client_class.return_value

        self.manager._connect_ssh()

        client.load_system_host_keys.assert_called_once_with()
        policy = client.set_missing_host_key_policy.call_args.args[0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)

    @patch.object(VirtualminAuthenticationManager, "_execute_ssh_command")
    def test_ssh_command_quotes_untrusted_parameter_values(self, mock_execute: MagicMock) -> None:
        mock_execute.return_value = Ok("created successfully")

        self.manager._execute_ssh_sudo("create-domain", {"domain": "example.com; touch /tmp/pwned"})

        mock_execute.assert_called_once_with(
            "sudo /usr/sbin/virtualmin create-domain --domain 'example.com; touch /tmp/pwned'"
        )
