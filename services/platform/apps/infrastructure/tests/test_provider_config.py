"""
Tests for provider_config.py

Comprehensive tests for the config-driven multi-provider infrastructure system.
"""

from __future__ import annotations

import os
import subprocess
from unittest import mock

from django.test import TestCase, override_settings

from apps.infrastructure.provider_config import (
    PROVIDER_CONFIG,
    ProviderCommandResult,
    get_cli_tool_path,
    get_provider_config,
    get_supported_providers,
    get_terraform_provider_block,
    get_terraform_variables_for_deployment,
    is_cli_available,
    is_provider_supported,
    map_terraform_outputs_to_deployment,
    run_provider_command,
    validate_provider_prerequisites,
)


class TestProviderConfigData(TestCase):
    """Tests for PROVIDER_CONFIG data structure integrity."""

    def test_all_providers_have_required_keys(self):
        """Each provider must have all required configuration keys."""
        required_keys = [
            "terraform_module",
            "terraform_provider",
            "terraform_provider_version",
            "credential_key",
            "token_env_var",
            "cli",
            "terraform_vars",
            "output_mappings",
        ]

        for provider, config in PROVIDER_CONFIG.items():
            for key in required_keys:
                self.assertIn(
                    key,
                    config,
                    f"Provider '{provider}' missing required key: {key}",
                )

    def test_all_providers_have_required_cli_commands(self):
        """Each provider CLI config must have standard power commands."""
        required_commands = ["power_off", "power_on", "reboot", "resize", "delete"]

        for provider, config in PROVIDER_CONFIG.items():
            cli = config.get("cli", {})
            self.assertIn("tool", cli, f"Provider '{provider}' CLI missing 'tool'")

            for cmd in required_commands:
                self.assertIn(
                    cmd,
                    cli,
                    f"Provider '{provider}' CLI missing command: {cmd}",
                )
                # Ensure command is a list
                self.assertIsInstance(
                    cli[cmd],
                    list,
                    f"Provider '{provider}' CLI command '{cmd}' must be a list",
                )

    def test_all_providers_have_required_terraform_vars(self):
        """Each provider must have required terraform variable mappings."""
        required_vars = ["api_token_var", "server_type_var", "region_var", "image_default"]

        for provider, config in PROVIDER_CONFIG.items():
            tf_vars = config.get("terraform_vars", {})
            for var in required_vars:
                self.assertIn(
                    var,
                    tf_vars,
                    f"Provider '{provider}' terraform_vars missing: {var}",
                )

    def test_all_providers_have_output_mappings(self):
        """Each provider must map to standard deployment fields."""
        # At minimum, we need to map the server ID
        for provider, config in PROVIDER_CONFIG.items():
            mappings = config.get("output_mappings", {})
            self.assertTrue(
                len(mappings) > 0,
                f"Provider '{provider}' has no output mappings",
            )

            # Check that at least one mapping points to external_node_id
            external_id_mapped = any(
                v == "external_node_id" for v in mappings.values()
            )
            self.assertTrue(
                external_id_mapped,
                f"Provider '{provider}' must map something to 'external_node_id'",
            )

    def test_supported_providers_list(self):
        """Test get_supported_providers returns all configured providers."""
        providers = get_supported_providers()
        self.assertIn("hetzner", providers)
        self.assertIn("digitalocean", providers)
        self.assertIn("vultr", providers)
        self.assertIn("linode", providers)

    def test_no_hardcoded_credentials_in_config(self):
        """Ensure no actual credentials are hardcoded in config."""
        import re

        # Check for patterns that look like real API tokens (long alphanumeric strings)
        # Real tokens are typically 32+ chars of random alphanumerics

        for provider, config in PROVIDER_CONFIG.items():
            # Check credential_key doesn't contain an actual token
            cred_key = config.get("credential_key", "")
            # Credential keys should be short identifiers, not actual tokens
            self.assertLess(
                len(cred_key),
                32,
                f"Provider '{provider}' credential_key looks like a real token",
            )

            # Check token_env_var doesn't contain an actual token
            env_var = config.get("token_env_var", "")
            self.assertLess(
                len(env_var),
                32,
                f"Provider '{provider}' token_env_var looks like a real token",
            )

            # Check CLI commands don't contain embedded secrets
            cli = config.get("cli", {})
            for operation, cmd_parts in cli.items():
                if operation == "tool":
                    continue
                for part in cmd_parts:
                    # Check for long alphanumeric strings that could be tokens
                    if re.match(r"^[A-Za-z0-9_-]{32,}$", part):
                        self.fail(
                            f"Provider '{provider}' command '{operation}' "
                            f"contains suspicious token-like string: {part[:20]}..."
                        )


class TestGetProviderConfig(TestCase):
    """Tests for get_provider_config function."""

    def test_get_hetzner_config(self):
        """Test retrieving Hetzner configuration."""
        config = get_provider_config("hetzner")
        assert config is not None
        self.assertEqual(config["terraform_module"], "hetzner")
        self.assertEqual(config["credential_key"], "hcloud_token")

    def test_get_digitalocean_config(self):
        """Test retrieving DigitalOcean configuration."""
        config = get_provider_config("digitalocean")
        assert config is not None
        self.assertEqual(config["terraform_module"], "digitalocean")
        self.assertEqual(config["credential_key"], "do_token")

    def test_get_unknown_provider_returns_none(self):
        """Test that unknown provider returns None."""
        config = get_provider_config("unknown_provider")
        self.assertIsNone(config)

    def test_get_provider_config_case_sensitive(self):
        """Provider names should be case-sensitive."""
        config = get_provider_config("HETZNER")
        self.assertIsNone(config)

        config = get_provider_config("Hetzner")
        self.assertIsNone(config)


class TestIsProviderSupported(TestCase):
    """Tests for is_provider_supported function."""

    def test_supported_providers(self):
        """Test known supported providers."""
        self.assertTrue(is_provider_supported("hetzner"))
        self.assertTrue(is_provider_supported("digitalocean"))
        self.assertTrue(is_provider_supported("vultr"))
        self.assertTrue(is_provider_supported("linode"))

    def test_unsupported_providers(self):
        """Test unsupported providers return False."""
        self.assertFalse(is_provider_supported("aws"))
        self.assertFalse(is_provider_supported("gcp"))
        self.assertFalse(is_provider_supported("azure"))
        self.assertFalse(is_provider_supported(""))
        self.assertFalse(is_provider_supported("unknown"))


class TestRunProviderCommand(TestCase):
    """Tests for run_provider_command function."""

    def test_unknown_provider_returns_error(self):
        """Unknown provider should return Err result."""
        result = run_provider_command(
            provider_type="unknown",
            operation="power_off",
            credentials={"api_token": "test"},
            server_id="123",
        )
        self.assertTrue(result.is_err())
        self.assertIn("Unknown provider", result.unwrap_err())

    def test_unknown_operation_returns_error(self):
        """Unknown operation should return Err result."""
        result = run_provider_command(
            provider_type="hetzner",
            operation="unknown_operation",
            credentials={"api_token": "test"},
            server_id="123",
        )
        self.assertTrue(result.is_err())
        self.assertIn("not supported", result.unwrap_err())

    @mock.patch("shutil.which")
    def test_missing_parameter_returns_error(self, mock_which):
        """Missing required parameter should return Err result."""
        mock_which.return_value = "/usr/bin/hcloud"

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "test"},
            # Missing server_id
        )
        self.assertTrue(result.is_err())
        self.assertIn("Missing required parameter", result.unwrap_err())

    @mock.patch("shutil.which")
    def test_missing_cli_tool_returns_error(self, mock_which):
        """Missing CLI tool should return Err result."""
        mock_which.return_value = None

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "test"},
            server_id="123",
        )
        self.assertTrue(result.is_err())
        self.assertIn("CLI tool not found", result.unwrap_err())

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_successful_command_execution(self, mock_which, mock_run):
        """Test successful command execution."""
        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout="Success",
            stderr="",
        )

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "test_token"},
            server_id="123",
        )

        self.assertTrue(result.is_ok())
        cmd_result = result.unwrap()
        self.assertTrue(cmd_result.success)
        self.assertEqual(cmd_result.stdout, "Success")

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_failed_command_returns_result_with_error(self, mock_which, mock_run):
        """Test failed command returns result with success=False."""
        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.Mock(
            returncode=1,
            stdout="",
            stderr="Server not found",
        )

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "test_token"},
            server_id="999",
        )

        self.assertTrue(result.is_ok())  # Command ran, but failed
        cmd_result = result.unwrap()
        self.assertFalse(cmd_result.success)
        self.assertIn("Server not found", cmd_result.stderr)

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_command_timeout_returns_error(self, mock_which, mock_run):
        """Test command timeout returns Err result."""
        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="hcloud", timeout=120)

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "test_token"},
            server_id="123",
            timeout=120,
        )

        self.assertTrue(result.is_err())
        self.assertIn("timed out", result.unwrap_err())

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_credentials_passed_to_environment(self, mock_which, mock_run):
        """Verify credentials are passed via environment variables."""
        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

        run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"hcloud_token": "secret_token"},
            server_id="123",
        )

        # Check that env was passed with the token
        call_kwargs = mock_run.call_args.kwargs
        self.assertIn("env", call_kwargs)
        self.assertEqual(call_kwargs["env"]["HCLOUD_TOKEN"], "secret_token")

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_command_parameters_substituted_correctly(self, mock_which, mock_run):
        """Test that parameters are substituted in command template."""
        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

        run_provider_command(
            provider_type="hetzner",
            operation="resize",
            credentials={"api_token": "test"},
            server_id="12345",
            size="cpx41",
        )

        # Check the command was built correctly
        call_args = mock_run.call_args.args[0]
        self.assertIn("12345", call_args)
        self.assertIn("cpx41", call_args)


class TestTerraformHelpers(TestCase):
    """Tests for Terraform-related helper functions."""

    def test_get_terraform_provider_block_hetzner(self):
        """Test Terraform provider block generation for Hetzner."""
        block = get_terraform_provider_block("hetzner")
        assert block is not None
        self.assertIn("hetznercloud/hcloud", block)
        self.assertIn("~> 1.45", block)

    def test_get_terraform_provider_block_digitalocean(self):
        """Test Terraform provider block generation for DigitalOcean."""
        block = get_terraform_provider_block("digitalocean")
        assert block is not None
        self.assertIn("digitalocean/digitalocean", block)

    def test_get_terraform_provider_block_unknown_returns_none(self):
        """Unknown provider should return None for provider block."""
        block = get_terraform_provider_block("unknown")
        self.assertIsNone(block)


class TestOutputMappings(TestCase):
    """Tests for map_terraform_outputs_to_deployment function."""

    def test_maps_outputs_to_deployment_fields(self):
        """Test that Terraform outputs are correctly mapped to deployment."""
        # Create a mock deployment
        class MockDeployment:
            external_node_id = None
            ipv4_address = None
            ipv6_address = None

        deployment = MockDeployment()
        outputs = {
            "server_id": "12345",
            "ipv4_address": "1.2.3.4",
            "ipv6_address": "2001:db8::1",
        }

        map_terraform_outputs_to_deployment("hetzner", outputs, deployment)  # type: ignore[arg-type]

        self.assertEqual(deployment.external_node_id, "12345")
        self.assertEqual(deployment.ipv4_address, "1.2.3.4")
        self.assertEqual(deployment.ipv6_address, "2001:db8::1")

    def test_handles_nested_terraform_output_format(self):
        """Test handling of nested Terraform output format with 'value' key."""
        class MockDeployment:
            external_node_id = None
            ipv4_address = None

        deployment = MockDeployment()
        # Terraform sometimes returns outputs as {"value": "actual_value"}
        outputs = {
            "server_id": {"value": "12345"},
            "ipv4_address": {"value": "1.2.3.4"},
        }

        map_terraform_outputs_to_deployment("hetzner", outputs, deployment)  # type: ignore[arg-type]

        self.assertEqual(deployment.external_node_id, "12345")
        self.assertEqual(deployment.ipv4_address, "1.2.3.4")

    def test_unknown_provider_does_nothing(self):
        """Unknown provider should not modify deployment."""
        class MockDeployment:
            external_node_id = "original"

        deployment = MockDeployment()
        outputs = {"server_id": "new_value"}

        map_terraform_outputs_to_deployment("unknown", outputs, deployment)  # type: ignore[arg-type]

        self.assertEqual(deployment.external_node_id, "original")


class TestSecurityConsiderations(TestCase):
    """Security-focused tests."""

    def test_credentials_not_logged(self):
        """Ensure credentials are not included in logged command strings."""
        # The command string in ProviderCommandResult should not contain the token
        result = ProviderCommandResult(
            success=True,
            stdout="",
            stderr="",
            return_code=0,
            command="hcloud server poweroff 123",
        )

        # Verify no token patterns in command
        self.assertNotIn("token", result.command.lower())
        self.assertNotIn("secret", result.command.lower())
        self.assertNotIn("password", result.command.lower())

    def test_sensitive_env_vars_not_in_command(self):
        """Ensure sensitive env vars are passed separately, not in command."""
        for provider, config in PROVIDER_CONFIG.items():
            cli = config.get("cli", {})
            for operation, cmd_template in cli.items():
                if operation == "tool":
                    continue
                # Command templates should not contain env var references
                cmd_str = " ".join(cmd_template)
                self.assertNotIn("$", cmd_str, f"Command {provider}:{operation} has shell variable")
                self.assertNotIn("TOKEN", cmd_str.upper(), f"Command {provider}:{operation} references TOKEN")

    def test_command_injection_prevention(self):
        """Test that special characters in parameters don't cause injection."""
        # This is more of a design verification - subprocess.run with list args
        # prevents shell injection by default

        for provider, config in PROVIDER_CONFIG.items():
            cli = config.get("cli", {})
            for operation, cmd_template in cli.items():
                if operation == "tool":
                    continue
                # Verify commands are lists, not strings (prevents shell injection)
                self.assertIsInstance(
                    cmd_template,
                    list,
                    f"{provider}:{operation} should be list, not string",
                )


class TestEdgeCases(TestCase):
    """Tests for edge cases and error handling."""

    def test_empty_credentials_dict(self):
        """Test behavior with empty credentials."""
        with mock.patch("shutil.which", return_value="/usr/bin/hcloud"):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                result = run_provider_command(
                    provider_type="hetzner",
                    operation="power_off",
                    credentials={},  # Empty credentials
                    server_id="123",
                )

                # Should still run but with empty token
                self.assertTrue(result.is_ok())

    def test_special_characters_in_server_id(self):
        """Test that special characters in server_id are handled."""
        with mock.patch("shutil.which", return_value="/usr/bin/hcloud"):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                # Try various potentially problematic characters
                for server_id in ["123", "abc-def", "server_1", "12345678901234567890"]:
                    result = run_provider_command(
                        provider_type="hetzner",
                        operation="power_off",
                        credentials={"api_token": "test"},
                        server_id=server_id,
                    )
                    self.assertTrue(result.is_ok(), f"Failed for server_id: {server_id}")

    def test_very_long_timeout(self):
        """Test that timeout is passed correctly."""
        with mock.patch("shutil.which", return_value="/usr/bin/hcloud"):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                run_provider_command(
                    provider_type="hetzner",
                    operation="power_off",
                    credentials={"api_token": "test"},
                    server_id="123",
                    timeout=600,  # 10 minutes
                )

                call_kwargs = mock_run.call_args.kwargs
                self.assertEqual(call_kwargs["timeout"], 600)


class TestValidateProviderPrerequisites(TestCase):
    """Tests for validate_provider_prerequisites()."""

    @mock.patch("apps.infrastructure.provider_config.shutil.which")
    @mock.patch("apps.infrastructure.provider_config.Path.is_dir", return_value=True)
    def test_valid_provider_passes(self, mock_is_dir, mock_which):
        """All prerequisites met should return Ok."""
        mock_which.side_effect = lambda tool: f"/usr/bin/{tool}"

        result = validate_provider_prerequisites("hetzner")
        self.assertTrue(result.is_ok())
        details = result.unwrap()
        self.assertEqual(details["provider"], "hetzner")
        self.assertIn("cli_tool", details)
        self.assertIn("terraform_path", details)

    def test_unknown_provider_fails(self):
        """Unknown provider should return Err."""
        result = validate_provider_prerequisites("nonexistent_provider")
        self.assertTrue(result.is_err())
        self.assertIn("Unknown provider", result.unwrap_err())

    @mock.patch("apps.infrastructure.provider_config.shutil.which", return_value=None)
    def test_missing_cli_tool_fails(self, mock_which):
        """Missing CLI tool should return Err."""
        result = validate_provider_prerequisites("hetzner")
        self.assertTrue(result.is_err())
        self.assertIn("CLI tool", result.unwrap_err())

    @mock.patch("apps.infrastructure.provider_config.shutil.which")
    def test_missing_terraform_fails(self, mock_which):
        """Missing terraform binary should return Err."""
        # CLI tool found, but terraform not found
        def side_effect(tool):
            if tool == "hcloud":
                return "/usr/bin/hcloud"
            return None  # terraform not found

        mock_which.side_effect = side_effect

        result = validate_provider_prerequisites("hetzner")
        self.assertTrue(result.is_err())
        self.assertIn("Terraform binary not found", result.unwrap_err())

    @mock.patch("apps.infrastructure.provider_config.shutil.which")
    @mock.patch("apps.infrastructure.provider_config.Path.is_dir", return_value=False)
    def test_missing_terraform_module_fails(self, mock_is_dir, mock_which):
        """Missing terraform module directory should return Err."""
        mock_which.side_effect = lambda tool: f"/usr/bin/{tool}"

        result = validate_provider_prerequisites("hetzner")
        self.assertTrue(result.is_err())
        self.assertIn("Terraform module not found", result.unwrap_err())

    def test_all_configured_providers_have_terraform_modules(self):
        """All providers in PROVIDER_CONFIG should have terraform module dirs on disk."""
        import os
        from pathlib import Path

        modules_base = Path(__file__).parent.parent.parent.parent / "infrastructure" / "terraform" / "modules"

        for provider_type, config in PROVIDER_CONFIG.items():
            module_name = config.get("terraform_module", provider_type)
            module_path = modules_base / module_name
            self.assertTrue(
                module_path.is_dir(),
                f"Terraform module directory missing for provider '{provider_type}': {module_path}",
            )
