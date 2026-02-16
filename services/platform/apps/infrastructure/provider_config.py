"""
Cloud Provider Configuration

Config-driven multi-provider support for infrastructure deployment.
All provider-specific details are defined as data, not code.

Usage:
    from apps.infrastructure.provider_config import get_provider_config, run_provider_command

    # Get config for a provider
    config = get_provider_config("hetzner")

    # Run a provider command
    result = run_provider_command(
        provider_type="hetzner",
        operation="power_off",
        credentials={"api_token": "xxx"},
        server_id="12345",
    )
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import CloudProvider, NodeDeployment

logger = logging.getLogger(__name__)


# =============================================================================
# Provider Configuration - All provider-specific details as data
# =============================================================================

PROVIDER_CONFIG: dict[str, dict[str, Any]] = {
    "hetzner": {
        # Terraform configuration
        "terraform_module": "hetzner",
        "terraform_provider": "hetznercloud/hcloud",
        "terraform_provider_version": "~> 1.45",
        # Credentials
        "credential_key": "hcloud_token",
        "token_env_var": "HCLOUD_TOKEN",
        # CLI tool configuration
        "cli": {
            "tool": "hcloud",
            "power_off": ["server", "poweroff", "{server_id}"],
            "power_on": ["server", "poweron", "{server_id}"],
            "reboot": ["server", "reboot", "{server_id}"],
            "resize": ["server", "change-type", "--server", "{server_id}", "--type", "{size}"],
            "delete": ["server", "delete", "{server_id}"],
        },
        # Terraform variable mapping
        "terraform_vars": {
            "api_token_var": "hcloud_token",
            "server_type_var": "server_type",
            "region_var": "location",
            "image_default": "ubuntu-22.04",
        },
        # Output field mappings (terraform output -> model field)
        "output_mappings": {
            "server_id": "external_node_id",
            "ipv4_address": "ipv4_address",
            "ipv6_address": "ipv6_address",
        },
    },
    "digitalocean": {
        # Terraform configuration
        "terraform_module": "digitalocean",
        "terraform_provider": "digitalocean/digitalocean",
        "terraform_provider_version": "~> 2.34",
        # Credentials
        "credential_key": "do_token",
        "token_env_var": "DIGITALOCEAN_TOKEN",
        # CLI tool configuration
        "cli": {
            "tool": "doctl",
            "power_off": ["compute", "droplet-action", "power-off", "{server_id}", "--wait"],
            "power_on": ["compute", "droplet-action", "power-on", "{server_id}", "--wait"],
            "reboot": ["compute", "droplet-action", "reboot", "{server_id}", "--wait"],
            "resize": ["compute", "droplet-action", "resize", "{server_id}", "--size", "{size}", "--wait"],
            "delete": ["compute", "droplet", "delete", "{server_id}", "--force"],
        },
        # Terraform variable mapping
        "terraform_vars": {
            "api_token_var": "do_token",
            "server_type_var": "size",
            "region_var": "region",
            "image_default": "ubuntu-22-04-x64",
        },
        # Output field mappings
        "output_mappings": {
            "droplet_id": "external_node_id",
            "ipv4_address": "ipv4_address",
            "ipv6_address": "ipv6_address",
        },
    },
    "vultr": {
        # Terraform configuration
        "terraform_module": "vultr",
        "terraform_provider": "vultr/vultr",
        "terraform_provider_version": "~> 2.19",
        # Credentials
        "credential_key": "vultr_api_key",
        "token_env_var": "VULTR_API_KEY",
        # CLI tool configuration
        "cli": {
            "tool": "vultr-cli",
            "power_off": ["instance", "stop", "{server_id}"],
            "power_on": ["instance", "start", "{server_id}"],
            "reboot": ["instance", "restart", "{server_id}"],
            "resize": ["instance", "update", "{server_id}", "--plan", "{size}"],
            "delete": ["instance", "delete", "{server_id}"],
        },
        # Terraform variable mapping
        "terraform_vars": {
            "api_token_var": "vultr_api_key",
            "server_type_var": "plan",
            "region_var": "region",
            "image_default": "ubuntu-22-04-x64",
        },
        # Output field mappings
        "output_mappings": {
            "instance_id": "external_node_id",
            "main_ip": "ipv4_address",
            "v6_main_ip": "ipv6_address",
        },
    },
    "linode": {
        # Terraform configuration
        "terraform_module": "linode",
        "terraform_provider": "linode/linode",
        "terraform_provider_version": "~> 2.12",
        # Credentials
        "credential_key": "linode_token",
        "token_env_var": "LINODE_TOKEN",
        # CLI tool configuration
        "cli": {
            "tool": "linode-cli",
            "power_off": ["linodes", "shutdown", "{server_id}"],
            "power_on": ["linodes", "boot", "{server_id}"],
            "reboot": ["linodes", "reboot", "{server_id}"],
            "resize": ["linodes", "resize", "{server_id}", "--type", "{size}"],
            "delete": ["linodes", "delete", "{server_id}"],
        },
        # Terraform variable mapping
        "terraform_vars": {
            "api_token_var": "linode_token",
            "server_type_var": "type",
            "region_var": "region",
            "image_default": "linode/ubuntu22.04",
        },
        # Output field mappings
        "output_mappings": {
            "id": "external_node_id",
            "ip_address": "ipv4_address",
            "ipv6": "ipv6_address",
        },
    },
}


# =============================================================================
# Provider Configuration Access
# =============================================================================


def get_provider_config(provider_type: str) -> dict[str, Any] | None:
    """
    Get configuration for a specific provider.

    Args:
        provider_type: Provider type key (e.g., "hetzner", "digitalocean")

    Returns:
        Provider configuration dict or None if not found
    """
    return PROVIDER_CONFIG.get(provider_type)


def get_supported_providers() -> list[str]:
    """Get list of supported provider types."""
    return list(PROVIDER_CONFIG.keys())


def is_provider_supported(provider_type: str) -> bool:
    """Check if a provider type is supported."""
    return provider_type in PROVIDER_CONFIG


def get_cli_tool_path(provider_type: str) -> str | None:
    """
    Get the CLI tool path for a provider.

    Returns the path to the CLI tool if found, None otherwise.
    """
    config = get_provider_config(provider_type)
    if not config:
        return None

    tool_name = config["cli"]["tool"]
    return shutil.which(tool_name)


def is_cli_available(provider_type: str) -> bool:
    """Check if the CLI tool for a provider is available."""
    return get_cli_tool_path(provider_type) is not None


# =============================================================================
# Provider Command Execution
# =============================================================================


@dataclass
class ProviderCommandResult:
    """Result of a provider CLI command execution."""

    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str


def run_provider_command(  # noqa: PLR0911
    provider_type: str,
    operation: str,
    credentials: dict[str, str],
    timeout: int = 120,
    **kwargs: str,
) -> Result[ProviderCommandResult, str]:
    """
    Execute a provider CLI command.

    This is the single, generic function that handles all provider CLI operations.
    It builds commands from configuration and substitutes parameters.

    Args:
        provider_type: Provider type (e.g., "hetzner", "digitalocean")
        operation: Operation name (e.g., "power_off", "power_on", "reboot", "resize")
        credentials: Dict with credential key-value pairs
        timeout: Command timeout in seconds
        **kwargs: Parameters to substitute in command (e.g., server_id="123", size="cpx31")

    Returns:
        Result with ProviderCommandResult or error message

    Example:
        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"api_token": "xxx"},
            server_id="12345678",
        )
    """
    # Get provider config
    config = get_provider_config(provider_type)
    if not config:
        return Err(f"Unknown provider: {provider_type}")

    # Get CLI config
    cli_config = config.get("cli")
    if not cli_config:
        return Err(f"No CLI configuration for provider: {provider_type}")

    # Get command template
    cmd_template = cli_config.get(operation)
    if not cmd_template:
        return Err(f"Operation '{operation}' not supported for provider: {provider_type}")

    # Get CLI tool
    tool_name = cli_config["tool"]
    tool_path = shutil.which(tool_name)
    if not tool_path:
        return Err(f"CLI tool not found: {tool_name}")

    # Build command with parameter substitutions
    try:
        cmd_args = [arg.format(**kwargs) for arg in cmd_template]
    except KeyError as e:
        return Err(f"Missing required parameter: {e}")

    cmd = [tool_path, *cmd_args]
    cmd_str = " ".join(cmd)

    # Build environment with credentials
    env = os.environ.copy()
    token_env_var = config.get("token_env_var")
    credential_key = config.get("credential_key")

    if token_env_var and credential_key:
        token_value = credentials.get(credential_key) or credentials.get("api_token", "")
        if token_value:
            env[token_env_var] = token_value

    logger.info(f"[Provider:{provider_type}] Running: {operation} (tool: {tool_name})")
    logger.debug(f"[Provider:{provider_type}] Command: {cmd_str}")

    # Execute command
    try:
        result = subprocess.run(  # noqa: PLW1510, S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        cmd_result = ProviderCommandResult(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            command=cmd_str,
        )

        if cmd_result.success:
            logger.info(f"[Provider:{provider_type}] {operation} completed successfully")
        else:
            logger.error(f"[Provider:{provider_type}] {operation} failed: {result.stderr[:200]}")

        return Ok(cmd_result)

    except subprocess.TimeoutExpired:
        logger.error(f"[Provider:{provider_type}] {operation} timed out after {timeout}s")
        return Err(f"Command timed out after {timeout} seconds")

    except Exception as e:
        logger.exception(f"[Provider:{provider_type}] {operation} failed: {e}")
        return Err(f"Command execution failed: {e}")


# =============================================================================
# Terraform Configuration Helpers
# =============================================================================


def get_terraform_module_path(provider_type: str, base_path: str) -> str | None:
    """
    Get the Terraform module path for a provider.

    Args:
        provider_type: Provider type
        base_path: Base path to terraform modules directory

    Returns:
        Full path to the provider's terraform module or None
    """
    config = get_provider_config(provider_type)
    if not config:
        return None

    module_name = config.get("terraform_module")
    if not module_name:
        return None

    return f"{base_path}/{module_name}"


def get_terraform_provider_block(provider_type: str) -> str | None:
    """
    Generate Terraform provider configuration block.

    Args:
        provider_type: Provider type

    Returns:
        Terraform HCL string for required_providers block or None
    """
    config = get_provider_config(provider_type)
    if not config:
        return None

    provider = config.get("terraform_provider")
    version = config.get("terraform_provider_version")

    if not provider:
        return None

    # Extract provider name (e.g., "hcloud" from "hetznercloud/hcloud")
    provider_name = provider.split("/")[-1] if "/" in provider else provider

    return f"""
    {provider_name} = {{
      source  = "{provider}"
      version = "{version}"
    }}"""


def get_terraform_variables_for_deployment(
    deployment: NodeDeployment,
    credentials: dict[str, str],
    ssh_public_key: str,
) -> dict[str, Any]:
    """
    Get Terraform variables for a deployment based on provider config.

    Args:
        deployment: NodeDeployment instance
        credentials: Provider credentials
        ssh_public_key: SSH public key for the server

    Returns:
        Dict of Terraform variables
    """
    provider_type = deployment.provider.provider_type
    config = get_provider_config(provider_type)

    if not config:
        return {}

    tf_vars = config.get("terraform_vars", {})

    return {
        tf_vars.get("api_token_var", "api_token"): credentials.get(config.get("credential_key", "api_token"), ""),
        "deployment_id": str(deployment.id),
        "hostname": deployment.hostname,
        "fqdn": deployment.fqdn,
        "environment": deployment.environment,
        "node_type": deployment.node_type,
        tf_vars.get("server_type_var", "server_type"): (
            deployment.node_size.provider_type_id if deployment.node_size else ""
        ),
        tf_vars.get("region_var", "region"): (deployment.region.provider_region_id if deployment.region else ""),
        "server_image": tf_vars.get("image_default", "ubuntu-22.04"),
        "ssh_public_key": ssh_public_key,
    }


def map_terraform_outputs_to_deployment(
    provider_type: str,
    outputs: dict[str, Any],
    deployment: NodeDeployment,
) -> None:
    """
    Map Terraform outputs to deployment model fields based on provider config.

    Args:
        provider_type: Provider type
        outputs: Terraform outputs dict
        deployment: NodeDeployment to update
    """
    config = get_provider_config(provider_type)
    if not config:
        return

    mappings = config.get("output_mappings", {})

    for tf_output, model_field in mappings.items():
        if tf_output in outputs:
            value = outputs[tf_output]
            # Handle nested output format from terraform
            if isinstance(value, dict) and "value" in value:
                value = value["value"]
            setattr(deployment, model_field, value)


# =============================================================================
# Credential Helpers
# =============================================================================


def validate_provider_prerequisites(
    provider_type: str,
    base_terraform_path: str | None = None,
) -> Result[dict[str, Any], str]:
    """
    Validate all prerequisites for a provider deployment.

    Checks:
    - Provider config exists
    - CLI tool is installed and accessible
    - Terraform binary is available
    - Provider terraform module exists on disk

    Args:
        provider_type: Provider type key (e.g., "hetzner", "digitalocean")
        base_terraform_path: Base path to terraform modules. If None, uses default.

    Returns:
        Result with validation details dict or error message
    """
    # 1. Check provider config exists
    config = get_provider_config(provider_type)
    if not config:
        return Err(f"Unknown provider: {provider_type}")

    details: dict[str, Any] = {"provider": provider_type}

    # 2. Check CLI tool is available
    cli_tool = config.get("cli", {}).get("tool", "")
    cli_path = shutil.which(cli_tool) if cli_tool else None
    if not cli_path:
        return Err(
            f"CLI tool '{cli_tool}' not found for provider '{provider_type}'. Please install it before deploying."
        )
    details["cli_tool"] = cli_tool
    details["cli_path"] = cli_path

    # 3. Check terraform is available
    terraform_path = shutil.which("terraform")
    if not terraform_path:
        return Err("Terraform binary not found. Please install Terraform >= 1.5.0.")
    details["terraform_path"] = terraform_path

    # 4. Check terraform module directory exists
    if base_terraform_path is None:
        base_terraform_path = str(Path(__file__).parent.parent.parent / "infrastructure" / "terraform" / "modules")
    module_name = config.get("terraform_module", provider_type)
    module_path = Path(base_terraform_path) / module_name
    if not module_path.is_dir():
        return Err(f"Terraform module not found at '{module_path}' for provider '{provider_type}'.")
    details["module_path"] = str(module_path)

    logger.info(f"✅ [Provider:{provider_type}] All prerequisites validated")
    return Ok(details)


def get_credentials_for_provider(
    provider: CloudProvider,
) -> Result[dict[str, str], str]:
    """
    Get credentials for a provider from the credential vault.

    Args:
        provider: CloudProvider instance

    Returns:
        Result with credentials dict or error
    """
    from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415

    vault = get_credential_vault()
    config = get_provider_config(provider.provider_type)

    if not config:
        return Err(f"Unknown provider type: {provider.provider_type}")

    credential_key = config.get("credential_key", "api_token")

    try:
        # Get credential from vault using provider's credential_identifier
        secret = vault.get_secret(provider.credential_identifier)
        if not secret:
            return Err(f"No credentials found for provider: {provider.name}")

        return Ok({credential_key: secret, "api_token": secret})

    except Exception as e:
        logger.error(f"Failed to get credentials for {provider.name}: {e}")
        return Err(f"Failed to retrieve credentials: {e}")
