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

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.provisioning.virtualmin_auth_manager import (
    AuthMethod,
    VirtualminAuthenticationManager,
)
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminAuthError,
    VirtualminAuthorizationError,
    VirtualminGateway,
    VirtualminRateLimitedError,
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

    @patch.object(VirtualminAuthenticationManager, "_get_auth_method_priority")
    @patch.object(VirtualminAuthenticationManager, "_execute_with_method")
    def test_non_authentication_error_preserves_retriability(
        self,
        mock_execute: MagicMock,
        mock_priority: MagicMock,
    ) -> None:
        mock_priority.return_value = [AuthMethod.ACL]
        mock_execute.return_value = Err(
            VirtualminAPIError("rate limited"),
            retriability=Retriability.RETRIABLE,
        )

        result = self.manager.execute_virtualmin_command("create-domain", {})

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)

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

    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway.call")
    def test_acl_preserves_retriability_of_raised_rate_limit(self, mock_call: MagicMock) -> None:
        # gateway.call RAISES the rate-limit error (429 is not a RequestException,
        # so the gateway retry loop does not catch it). The conversion to Err must
        # keep it RETRIABLE, or a rate-limited request is treated as terminal.
        mock_call.side_effect = VirtualminRateLimitedError("429", "host", "list-domains")

        result = self.manager._execute_acl_auth("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)

    @override_settings(VIRTUALMIN_MASTER_USERNAME="root", VIRTUALMIN_MASTER_PASSWORD="secret")
    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway.call")
    def test_master_proxy_preserves_retriability_of_raised_rate_limit(self, mock_call: MagicMock) -> None:
        mock_call.side_effect = VirtualminRateLimitedError("429", "host", "list-domains")

        result = self.manager._execute_master_proxy("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)

    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway.call")
    def test_acl_preserves_gateway_retriability(self, mock_call: MagicMock) -> None:
        mock_call.return_value = Err(
            VirtualminAPIError("rate limited"),
            retriability=Retriability.RETRIABLE,
        )

        result = self.manager._execute_acl_auth("list-domains", {})

        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)

    @override_settings(VIRTUALMIN_MASTER_USERNAME="root", VIRTUALMIN_MASTER_PASSWORD="secret")
    @patch("apps.provisioning.virtualmin_auth_manager.VirtualminGateway.call")
    def test_master_proxy_preserves_gateway_retriability(self, mock_call: MagicMock) -> None:
        mock_call.return_value = Err(
            VirtualminAPIError("rate limited"),
            retriability=Retriability.RETRIABLE,
        )

        result = self.manager._execute_master_proxy("list-domains", {})

        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)

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


class AuthorizationDenialDoesNotEscalateTests(TestCase):
    """403 ACL authorization denial must be terminal. Escalating to master/root
    would bypass the ACL the node deliberately enforced — and, against a
    compromised node returning 403, would hand it master credentials."""

    def setUp(self) -> None:
        self.mock_server = MagicMock()
        self.mock_server.hostname = "node.example.com"
        self.mock_server.id = 7
        self.manager = VirtualminAuthenticationManager(self.mock_server)

    @patch.object(VirtualminAuthenticationManager, "_cache_failed_auth_method")
    @patch.object(VirtualminAuthenticationManager, "_get_auth_method_priority")
    @patch.object(VirtualminAuthenticationManager, "_execute_with_method")
    def test_authorization_denial_never_escalates(
        self,
        mock_execute: MagicMock,
        mock_priority: MagicMock,
        _cache_failed: MagicMock,
    ) -> None:
        mock_priority.return_value = [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO]
        # ACL account authenticated but is forbidden (403); master would succeed
        # but must never be reached.
        mock_execute.side_effect = [
            Err(VirtualminAuthorizationError("Access forbidden - check ACL permissions")),
            Ok({"success": True}),
        ]

        result = self.manager.execute_virtualmin_command("delete-domain", {})

        self.assertTrue(result.is_err())
        mock_execute.assert_called_once_with(AuthMethod.ACL, "delete-domain", {})


class GatewayHttpStatusClassificationTests(TestCase):
    """401 (authentication) and 403 (authorization) must be distinct types so the
    auth manager can escalate on the former but never the latter."""

    @staticmethod
    def _gateway_and_response(status_code: int) -> tuple[VirtualminGateway, MagicMock]:
        gateway = object.__new__(VirtualminGateway)
        gateway.server = MagicMock()
        gateway.server.hostname = "node.example.com"
        response = MagicMock()
        response.status_code = status_code
        return gateway, response

    def test_401_maps_to_authentication_error_not_authorization(self) -> None:
        gateway, response = self._gateway_and_response(401)
        with self.assertRaises(VirtualminAuthError) as ctx:
            gateway._validate_http_status(response)
        self.assertNotIsInstance(ctx.exception, VirtualminAuthorizationError)

    def test_403_maps_to_authorization_error(self) -> None:
        gateway, response = self._gateway_and_response(403)
        with self.assertRaises(VirtualminAuthorizationError):
            gateway._validate_http_status(response)
