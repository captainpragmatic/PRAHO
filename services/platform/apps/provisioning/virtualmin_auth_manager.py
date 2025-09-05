"""
Virtualmin Authentication Fallback System - PRAHO Platform
Multi-path authentication with ACL risk mitigation.

ACL authentication potentially being "fixed" by Virtualmin updates.

#TODO - review later to see if this is over-engineered.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import Any

import paramiko  # type: ignore[import-untyped]
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

# TODO: Replace with proper Result types when circular dependency is resolved
from .virtualmin_gateway import VirtualminConfig, VirtualminGateway
from .virtualmin_models import VirtualminServer


# Temporary Result type implementation
class Result:
    def __init__(self, success: bool, value: Any = None, error: str | None = None):
        self._success = success
        self._value = value
        self._error = error

    def is_ok(self) -> bool:
        return self._success

    def unwrap(self) -> Any:
        if not self._success:
            raise RuntimeError(self._error)
        return self._value

    def unwrap_err(self) -> str:
        if self._success:
            raise RuntimeError("Cannot unwrap error from successful result")
        return self._error or "Unknown error"

    def is_err(self) -> bool:
        return not self._success


def create_ok_result(value: Any) -> Result:
    """Create a successful result."""
    return Result(True, value)


def create_error_result(error: str) -> Result:
    """Create an error result."""
    return Result(False, error=error)


logger = logging.getLogger(__name__)

# Authentication method constants
AUTH_METHOD_ACL = "acl"
AUTH_METHOD_MASTER_PROXY = "master_proxy"
AUTH_METHOD_SSH_SUDO = "ssh_sudo"

# Cache keys for auth method tracking
CACHE_AUTH_METHOD_PREFIX = "virtualmin_auth_method_"
CACHE_AUTH_HEALTH_PREFIX = "virtualmin_auth_health_"
CACHE_TIMEOUT = 3600  # 1 hour

# SSH connection constants
SSH_TIMEOUT = 30
SSH_MAX_RETRIES = 3
SUDO_COMMAND_TIMEOUT = 60


class AuthMethod(Enum):
    """Authentication method enumeration"""

    ACL = "acl"
    MASTER_PROXY = "master_proxy"
    SSH_SUDO = "ssh_sudo"


@dataclass
class AuthResult:
    """Result of authentication attempt"""

    success: bool
    method: AuthMethod
    error: str | None = None
    response_time_ms: int | None = None


@dataclass
class SSHCredentials:
    """SSH credentials for sudo fallback"""

    hostname: str
    port: int = 22
    username: str = "virtualmin-praho"
    private_key_path: str | None = None
    password: str | None = None


class VirtualminAuthenticationManager:
    """
    🚨 CRITICAL: Multi-path authentication manager for ACL risk mitigation.

    Implements the 3-tier fallback strategy:
    1. PRIMARY: ACL user authentication (current, risky)
    2. SECONDARY: Master admin via proxy service
    3. TERTIARY: SSH + sudo to virtualmin CLI

    Auto-detects when ACL auth breaks and falls back seamlessly.
    """

    def __init__(self, server: VirtualminServer):
        self.server = server
        # TODO: Type hint will be fixed when paramiko is added to requirements
        self._ssh_client: Any = None

    def execute_virtualmin_command(
        self, program: str, parameters: dict[str, Any], force_method: AuthMethod | None = None
    ) -> Result[Any, Any]:  # type: ignore[type-arg]
        """
        Execute Virtualmin command with fallback authentication.

        Args:
            program: Virtualmin program to execute
            parameters: Command parameters
            force_method: Force specific auth method (for testing)

        Returns:
            Result with command output or error
        """
        start_time = timezone.now()

        # Determine authentication method to try
        methods_to_try = [force_method] if force_method else self._get_auth_method_priority()

        last_error = ""

        for method in methods_to_try:
            logger.info(f"🔐 [Virtualmin Auth] Trying {method.value} for {program} on {self.server.hostname}")

            try:
                result = self._execute_with_method(method, program, parameters)

                if result.is_ok():
                    # Success! Cache this method as working
                    self._cache_working_auth_method(method)

                    execution_time = (timezone.now() - start_time).total_seconds() * 1000
                    logger.info(
                        f"✅ [Virtualmin Auth] {method.value} succeeded for {program} in {execution_time:.0f}ms"
                    )

                    return result
                else:
                    error_msg = result.unwrap_err()
                    last_error = f"{method.value}: {error_msg}"
                    logger.warning(f"❌ [Virtualmin Auth] {method.value} failed: {error_msg}")

                    # Mark this method as failed
                    self._cache_failed_auth_method(method, error_msg)

            except Exception as e:
                last_error = f"{method.value}: {e!s}"
                logger.error(f"🔥 [Virtualmin Auth] {method.value} exception: {e}")
                self._cache_failed_auth_method(method, str(e))

        # All methods failed
        logger.error(f"🚨 [Virtualmin Auth] ALL methods failed for {program}: {last_error}")
        return create_error_result(f"All authentication methods failed. Last error: {last_error}")

    def _execute_with_method(self, method: AuthMethod, program: str, parameters: dict[str, Any]) -> Result[Any, Any]:  # type: ignore[type-arg]
        """Execute command with specific authentication method"""

        if method == AuthMethod.ACL:
            return self._execute_acl_auth(program, parameters)
        elif method == AuthMethod.MASTER_PROXY:
            return self._execute_master_proxy(program, parameters)
        elif method == AuthMethod.SSH_SUDO:
            return self._execute_ssh_sudo(program, parameters)
        else:
            return create_error_result(f"Unknown authentication method: {method}")  # type: ignore[unreachable]

    def _execute_acl_auth(self, program: str, parameters: dict[str, Any]) -> Result[Any, Any]:  # type: ignore[type-arg]
        """Execute using current ACL user authentication"""
        try:
            # Use existing gateway with ACL credentials
            config = VirtualminConfig.from_credentials(
                hostname=self.server.hostname,
                username=self.server.api_username,
                password=self.server.get_api_password(),
                port=self.server.api_port,
                use_ssl=self.server.use_ssl,
                verify_ssl=self.server.ssl_verify,
                timeout=30,
            )

            gateway = VirtualminGateway(config)
            return gateway.call(program, parameters)  # type: ignore[return-value]

        except Exception as e:
            return create_error_result(f"ACL authentication failed: {e!s}")

    def _execute_master_proxy(self, program: str, parameters: dict[str, Any]) -> Result[Any, Any]:  # type: ignore[type-arg]
        """Execute using master admin credentials via proxy service"""
        try:
            # Get master admin credentials from environment
            master_username = getattr(settings, "VIRTUALMIN_MASTER_USERNAME", None)
            master_password = getattr(settings, "VIRTUALMIN_MASTER_PASSWORD", None)

            if not master_username or not master_password:
                return create_error_result("Master admin credentials not configured")

            # Use master credentials with same gateway
            config = VirtualminConfig.from_credentials(
                hostname=self.server.hostname,
                username=master_username,
                password=master_password,
                port=self.server.api_port,
                use_ssl=self.server.use_ssl,
                verify_ssl=self.server.ssl_verify,
                timeout=30,
            )

            gateway = VirtualminGateway(config)
            result = gateway.call(program, parameters)

            if result.is_ok():
                logger.warning(
                    f"🚨 [Security] Using master admin credentials for {program} "
                    f"on {self.server.hostname} - ACL auth appears broken!"
                )

            return result  # type: ignore[return-value]

        except Exception as e:
            return create_error_result(f"Master proxy authentication failed: {e!s}")

    def _execute_ssh_sudo(self, program: str, parameters: dict[str, Any]) -> Result[Any, Any]:  # type: ignore[type-arg]
        """Execute using SSH + sudo to virtualmin CLI"""
        try:
            # Build virtualmin CLI command
            cmd_parts = ["/usr/sbin/virtualmin", program]

            # Add parameters
            for key, value in parameters.items():
                if value is True:
                    cmd_parts.append(f"--{key}")
                elif value is not None and value is not False:
                    cmd_parts.extend([f"--{key}", str(value)])

            command = " ".join(cmd_parts)

            # Execute via SSH
            ssh_result = self._execute_ssh_command(f"sudo {command}")

            if ssh_result.is_err():
                return ssh_result

            output = ssh_result.unwrap()

            # Parse CLI output (simpler than API response)
            if "successfully" in output.lower() or "created" in output.lower():
                return create_ok_result({"success": True, "message": output.strip()})
            elif "error" in output.lower() or "failed" in output.lower():
                return create_error_result(f"CLI command failed: {output.strip()}")
            else:
                return create_ok_result({"success": True, "message": output.strip()})

        except Exception as e:
            return create_error_result(f"SSH sudo authentication failed: {e!s}")

    def _execute_ssh_command(self, command: str) -> Result[Any, Any]:  # type: ignore[type-arg]
        """Execute command via SSH"""
        try:
            if not self._ssh_client:
                self._connect_ssh()

            if not self._ssh_client:
                return create_error_result("Failed to establish SSH connection")

            stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=SUDO_COMMAND_TIMEOUT)

            # Read output
            output = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                return create_error_result(f"Command failed (exit {exit_code}): {error}")

            return create_ok_result(output)

        except Exception as e:
            # Try to reconnect on failure
            self._disconnect_ssh()
            return create_error_result(f"SSH command execution failed: {e!s}")

    def _connect_ssh(self) -> None:
        """Establish SSH connection"""

        try:
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Get SSH credentials from settings
            ssh_username = getattr(settings, "VIRTUALMIN_SSH_USERNAME", "virtualmin-praho")
            ssh_private_key = getattr(settings, "VIRTUALMIN_SSH_PRIVATE_KEY_PATH", None)
            ssh_password = getattr(settings, "VIRTUALMIN_SSH_PASSWORD", None)

            if ssh_private_key:
                # Use private key authentication
                self._ssh_client.connect(
                    hostname=self.server.hostname,
                    port=22,
                    username=ssh_username,
                    key_filename=ssh_private_key,
                    timeout=SSH_TIMEOUT,
                )
            elif ssh_password:
                # Use password authentication
                self._ssh_client.connect(
                    hostname=self.server.hostname,
                    port=22,
                    username=ssh_username,
                    password=ssh_password,
                    timeout=SSH_TIMEOUT,
                )
            else:
                raise Exception("No SSH credentials configured")

            logger.info(f"✅ [SSH] Connected to {self.server.hostname}")

        except Exception as e:
            logger.error(f"❌ [SSH] Failed to connect to {self.server.hostname}: {e}")
            self._ssh_client = None
            raise

    def _disconnect_ssh(self) -> None:
        """Close SSH connection"""
        if self._ssh_client:
            with contextlib.suppress(BaseException):
                self._ssh_client.close()
            self._ssh_client = None

    def _get_auth_method_priority(self) -> list[AuthMethod]:
        """Get authentication methods in priority order"""
        cache_key = f"{CACHE_AUTH_METHOD_PREFIX}{self.server.id}"
        cached_method = cache.get(cache_key)

        if cached_method:
            # Start with the method that worked last time
            methods = [AuthMethod(cached_method)]

            # Add others as fallbacks
            all_methods = [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO]
            for method in all_methods:
                if method not in methods:
                    methods.append(method)

            return methods
        else:
            # Default priority order
            return [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO]

    def _cache_working_auth_method(self, method: AuthMethod) -> None:
        """Cache authentication method that worked"""
        cache_key = f"{CACHE_AUTH_METHOD_PREFIX}{self.server.id}"
        cache.set(cache_key, method.value, CACHE_TIMEOUT)

        # Clear any failure cache
        fail_cache_key = f"{CACHE_AUTH_HEALTH_PREFIX}{self.server.id}_{method.value}"
        cache.delete(fail_cache_key)

    def _cache_failed_auth_method(self, method: AuthMethod, error: str) -> None:
        """Cache authentication method failure"""
        fail_cache_key = f"{CACHE_AUTH_HEALTH_PREFIX}{self.server.id}_{method.value}"
        cache.set(fail_cache_key, error, 300)  # Cache failures for 5 minutes

    def health_check_all_methods(self) -> dict[str, AuthResult]:
        """Test all authentication methods for health monitoring"""
        results = {}

        # Test each method with a simple list-domains command
        for method in [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO]:
            start_time = timezone.now()

            try:
                result = self._execute_with_method(method, "list-domains", {"multiline": True})

                execution_time = (timezone.now() - start_time).total_seconds() * 1000

                if result.is_ok():
                    results[method.value] = AuthResult(
                        success=True, method=method, response_time_ms=int(execution_time)
                    )
                else:
                    results[method.value] = AuthResult(success=False, method=method, error=result.unwrap_err())

            except Exception as e:
                results[method.value] = AuthResult(success=False, method=method, error=str(e))

        return results

    def __enter__(self) -> VirtualminAuthenticationManager:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        self._disconnect_ssh()


# ===============================================================================
# HELPER FUNCTIONS FOR INTEGRATION
# ===============================================================================


def get_virtualmin_auth_manager(server: VirtualminServer) -> VirtualminAuthenticationManager:
    """Get authentication manager for a server"""
    return VirtualminAuthenticationManager(server)


def test_acl_authentication_health() -> dict[str, Any]:
    """
    Test ACL authentication health across all servers.

    Returns summary of which servers have working ACL auth
    and which need fallback methods.
    """
    results = {
        "servers_tested": 0,
        "acl_working": 0,
        "acl_failed": 0,
        "fallback_working": 0,
        "completely_failed": 0,
        "server_details": [],
    }

    servers = VirtualminServer.objects.filter(status="active")

    for server in servers:
        results["servers_tested"] += 1  # type: ignore[operator]

        with get_virtualmin_auth_manager(server) as auth_manager:
            health_results = auth_manager.health_check_all_methods()

            acl_result = health_results.get(AuthMethod.ACL.value)

            server_info = {
                "server_id": str(server.id),
                "hostname": server.hostname,
                "acl_working": acl_result.success if acl_result else False,
                "auth_methods": health_results,
            }

            if acl_result and acl_result.success:
                results["acl_working"] += 1  # type: ignore[operator]
                server_info["status"] = "acl_healthy"
            else:
                results["acl_failed"] += 1  # type: ignore[operator]

                # Check if any fallback method works
                fallback_working = any(
                    result.success for method, result in health_results.items() if method != AuthMethod.ACL.value
                )

                if fallback_working:
                    results["fallback_working"] += 1  # type: ignore[operator]
                    server_info["status"] = "fallback_available"
                else:
                    results["completely_failed"] += 1  # type: ignore[operator]
                    server_info["status"] = "all_failed"

            results["server_details"].append(server_info)  # type: ignore[attr-defined]

    return results
