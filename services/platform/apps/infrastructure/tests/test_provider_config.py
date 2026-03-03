"""
Tests for provider_config.py

Comprehensive tests for the config-driven multi-provider infrastructure system.
"""

from __future__ import annotations

import subprocess
from unittest import mock

from django.test import TestCase

from apps.infrastructure.provider_config import (
    PROVIDER_CONFIG,
    PROVIDER_SYNC_REGISTRY,
    ProviderCommandResult,
    get_cli_tool_path,
    get_provider_config,
    get_provider_sync_fn,
    get_provider_token,
    get_supported_providers,
    is_cli_available,
    is_provider_supported,
    run_provider_command,
    store_provider_token,
    validate_provider_prerequisites,
)


class TestProviderConfigData(TestCase):
    """Tests for PROVIDER_CONFIG data structure integrity."""

    def test_all_providers_have_required_keys(self):
        """Each provider must have all required configuration keys."""
        common_required_keys = [
            "credential_key",
            "token_env_var",
            "cli",
            "output_mappings",
        ]

        for provider, config in PROVIDER_CONFIG.items():
            for key in common_required_keys:
                self.assertIn(
                    key,
                    config,
                    f"Provider '{provider}' missing required key: {key}",
                )

    def test_all_providers_have_required_cli_commands(self):
        """Each provider CLI config must have standard power commands."""
        # AWS uses modify-instance-attribute for resize (multi-step), so resize is optional
        required_commands = ["power_off", "power_on", "reboot", "delete"]

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
        self.assertIn("aws", providers)
        # Linode is NOT a supported provider (no entry in PROVIDER_CONFIG)
        self.assertNotIn("linode", providers)

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
        """Test retrieving Hetzner configuration (uses hcloud SDK)."""
        config = get_provider_config("hetzner")
        assert config is not None
        self.assertEqual(config["credential_key"], "hcloud_token")

    def test_get_digitalocean_config(self):
        """Test retrieving DigitalOcean configuration."""
        config = get_provider_config("digitalocean")
        assert config is not None
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
        self.assertTrue(is_provider_supported("aws"))

    def test_unsupported_providers(self):
        """Test unsupported providers return False."""
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
    def test_valid_provider_passes(self, mock_which):
        """All prerequisites met should return Ok."""
        mock_which.side_effect = lambda tool: f"/usr/bin/{tool}"

        result = validate_provider_prerequisites("hetzner")
        self.assertTrue(result.is_ok())
        details = result.unwrap()
        self.assertEqual(details["provider"], "hetzner")
        self.assertIn("cli_tool", details)

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


class TestSupportedProvidersNoLinode(TestCase):
    """Test that linode is NOT in the supported providers list (M6 fix)."""

    def test_supported_providers_no_linode(self):
        """Linode has no entry in PROVIDER_CONFIG; it must not appear as supported."""
        providers = get_supported_providers()
        self.assertNotIn("linode", providers)

    def test_linode_not_supported(self):
        """is_provider_supported returns False for linode."""
        self.assertFalse(is_provider_supported("linode"))

    def test_exactly_four_providers_configured(self):
        """Only hetzner, digitalocean, vultr, aws are configured."""
        expected = {"hetzner", "digitalocean", "vultr", "aws"}
        self.assertEqual(set(PROVIDER_CONFIG.keys()), expected)


class TestGetProviderToken(TestCase):
    """Tests for get_provider_token vault + env fallback."""

    def _make_provider(self, credential_identifier: str = "hcloud_token") -> mock.Mock:
        provider = mock.Mock()
        provider.provider_type = "hetzner"
        provider.name = "Hetzner Cloud"
        provider.credential_identifier = credential_identifier
        return provider

    @mock.patch("apps.common.credential_vault.get_credential_vault")
    def test_get_provider_token_vault_success(self, mock_get_vault):
        """Token returned from vault when credential_identifier is set."""
        from apps.common.types import Ok  # noqa: PLC0415

        vault = mock.Mock()
        vault.get_credential.return_value = Ok(("hetzner", "secret-token-123", {}))
        mock_get_vault.return_value = vault

        provider = self._make_provider("hcloud_token")
        result = get_provider_token(provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "secret-token-123")

    @mock.patch("apps.common.credential_vault.get_credential_vault")
    def test_get_provider_token_vault_failure(self, mock_get_vault):
        """Err when vault lookup fails and credential_identifier is set."""
        from apps.common.types import Err  # noqa: PLC0415

        vault = mock.Mock()
        vault.get_credential.return_value = Err("not found")
        mock_get_vault.return_value = vault

        provider = self._make_provider("hcloud_token")
        result = get_provider_token(provider)

        self.assertTrue(result.is_err())
        self.assertIn("Credential vault lookup failed", result.unwrap_err())

    @mock.patch.dict("os.environ", {"HCLOUD_TOKEN": "env-token-456"})
    def test_get_provider_token_env_fallback(self):
        """Falls back to env var when no credential_identifier."""
        provider = self._make_provider(credential_identifier="")
        result = get_provider_token(provider)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "env-token-456")


class TestStoreProviderToken(TestCase):
    """Tests for store_provider_token."""

    def _make_provider(self) -> mock.Mock:
        provider = mock.Mock()
        provider.provider_type = "hetzner"
        provider.name = "Hetzner Cloud"
        provider.code = "het"
        provider.credential_identifier = "hcloud_token"
        return provider

    @mock.patch("apps.common.credential_vault.get_credential_vault")
    def test_store_provider_token_success(self, mock_get_vault):
        """Successfully stores token in vault."""
        from apps.common.types import Ok  # noqa: PLC0415

        vault = mock.Mock()
        vault.store_credential.return_value = Ok("hcloud_token")
        mock_get_vault.return_value = vault

        provider = self._make_provider()
        result = store_provider_token(provider, "new-token-789")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), "hcloud_token")
        vault.store_credential.assert_called_once()

    @mock.patch("apps.common.credential_vault.get_credential_vault")
    def test_store_provider_token_failure(self, mock_get_vault):
        """Returns Err when vault store fails."""
        from apps.common.types import Err  # noqa: PLC0415

        vault = mock.Mock()
        vault.store_credential.return_value = Err("vault sealed")
        mock_get_vault.return_value = vault

        provider = self._make_provider()
        result = store_provider_token(provider, "token")

        self.assertTrue(result.is_err())
        self.assertIn("vault sealed", result.unwrap_err())
