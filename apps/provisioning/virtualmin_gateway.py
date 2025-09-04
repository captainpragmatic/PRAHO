"""
Virtualmin API Gateway - PRAHO Platform
Secure API integration for Virtualmin server management with multi-path authentication.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError

from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

from .virtualmin_models import VirtualminServer
from .virtualmin_validators import VirtualminValidator

if TYPE_CHECKING:
    from apps.common.credential_vault import CredentialVault

    from .virtualmin_auth_manager import VirtualminAuthenticationManager

logger = logging.getLogger(__name__)

# ===============================================================================
# CONSTANTS
# ===============================================================================

# Domain parsing constants
DOMAIN_PARTS_MIN = 2  # Minimum parts required for domain line parsing
DOMAIN_USERNAME_INDEX = 1  # Index of username in domain parts
DOMAIN_DESCRIPTION_INDEX = 2  # Starting index of description in domain parts


def get_virtualmin_config() -> dict[str, Any]:
    """
    Get Virtualmin configuration from SystemSettings and credential vault.

    Uses the credential vault for sensitive data (API keys, passwords) and
    SystemSettings for operational configuration.

    Returns a dict that can be used to create VirtualminConfig with a server.
    """
    return {
        # Operational settings from database
        "hostname": SettingsService.get_setting("virtualmin.hostname", "localhost"),
        "port": SettingsService.get_setting("virtualmin.port", 10000),
        "ssl_verify": SettingsService.get_setting("virtualmin.ssl_verify", True),
        "timeout": SettingsService.get_setting("virtualmin.request_timeout_seconds", 30),
        "max_retries": SettingsService.get_setting("virtualmin.max_retries", 3),
        "rate_limit_qps": SettingsService.get_setting("virtualmin.rate_limit_qps", 10),
        "connection_pool_size": SettingsService.get_setting("virtualmin.connection_pool_size", 10),
        "rate_limit_max_calls_per_hour": SettingsService.get_setting("virtualmin.rate_limit_max_calls_per_hour", 100),
        "auth_health_check_interval": SettingsService.get_setting(
            "virtualmin.auth_health_check_interval_seconds", 3600
        ),
        "auth_fallback_enabled": SettingsService.get_setting("virtualmin.auth_fallback_enabled", True),
        "backup_retention_days": SettingsService.get_setting("virtualmin.backup_retention_days", 7),
        "backup_compression_enabled": SettingsService.get_setting("virtualmin.backup_compression_enabled", True),
        "domain_quota_default_mb": SettingsService.get_setting("virtualmin.domain_quota_default_mb", 1000),
        "bandwidth_quota_default_mb": SettingsService.get_setting("virtualmin.bandwidth_quota_default_mb", 10000),
        "mysql_enabled": SettingsService.get_setting("virtualmin.mysql_enabled", True),
        "postgresql_enabled": SettingsService.get_setting("virtualmin.postgresql_enabled", False),
        "php_version_default": SettingsService.get_setting("virtualmin.php_version_default", "8.1"),
        "ssl_auto_renewal_enabled": SettingsService.get_setting("virtualmin.ssl_auto_renewal_enabled", True),
        "monitoring_enabled": SettingsService.get_setting("virtualmin.monitoring_enabled", True),
        "log_retention_days": SettingsService.get_setting("virtualmin.log_retention_days", 30),
        # Security credentials from credential vault or environment fallback
        "admin_user": os.environ.get("VIRTUALMIN_ADMIN_USER", ""),
        "admin_password": os.environ.get("VIRTUALMIN_ADMIN_PASSWORD", ""),
        "pinned_cert_sha256": os.environ.get("VIRTUALMIN_PINNED_CERT_SHA256", ""),
    }


# Virtualmin API constants
VIRTUALMIN_API_TIMEOUT = 30  # seconds
VIRTUALMIN_MAX_RETRIES = 3
VIRTUALMIN_RATE_LIMIT_WINDOW = 3600  # 1 hour
VIRTUALMIN_RATE_LIMIT_MAX_CALLS = 100  # Max calls per hour per server
VIRTUALMIN_CONNECTION_POOL_SIZE = 10

# HTTP status code constants
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_BAD_REQUEST = 400

# Response size limits (DoS protection)
MAX_RESPONSE_SIZE_MB = 50
MAX_RESPONSE_SIZE_BYTES = MAX_RESPONSE_SIZE_MB * 1024 * 1024


@dataclass(frozen=True)
class VirtualminResponse:
    """Normalized Virtualmin API response"""

    success: bool
    data: dict[str, Any]
    raw_response: str
    http_status: int
    execution_time: float
    program: str
    server_hostname: str


@dataclass(frozen=True)
class VirtualminConfig:
    """Virtualmin server configuration"""

    server: VirtualminServer
    timeout: int = VIRTUALMIN_API_TIMEOUT
    verify_ssl: bool = True
    cert_fingerprint: str = ""
    use_credential_vault: bool = True

    @classmethod
    def from_credentials(  # noqa: PLR0913
        cls,
        hostname: str,
        username: str,
        password: str,
        *,
        port: int = 10000,
        use_ssl: bool = True,
        verify_ssl: bool = True,
        timeout: int = VIRTUALMIN_API_TIMEOUT,
        cert_fingerprint: str = "",
    ) -> VirtualminConfig:
        """
        Create VirtualminConfig from individual credentials (DRY helper)

        This factory method allows creating VirtualminConfig instances from individual
        connection parameters while maintaining the proper dataclass structure internally.

        Args:
            hostname: Virtualmin server hostname
            username: API username
            password: API password
            port: API port (default: 10000)
            use_ssl: Whether to use SSL (default: True)
            verify_ssl: Whether to verify SSL certificates (default: True)
            timeout: Request timeout in seconds
            cert_fingerprint: Expected SSL certificate fingerprint

        Returns:
            VirtualminConfig: Configured instance
        """
        # Create a temporary VirtualminServer-like object for the config
        # We can't create a real VirtualminServer because it requires database access
        from types import SimpleNamespace  # noqa: PLC0415

        temp_server = SimpleNamespace()
        temp_server.hostname = hostname
        temp_server.api_username = username
        temp_server.api_port = port
        temp_server.use_ssl = use_ssl
        temp_server.ssl_verify = verify_ssl
        temp_server.ssl_cert_fingerprint = cert_fingerprint

        # Store the password directly (bypass get_api_password method)
        temp_server._api_password = password
        temp_server.get_api_password = lambda: password

        return cls(
            server=temp_server,  # type: ignore[arg-type]  # We know this works
            timeout=timeout,
            verify_ssl=verify_ssl,
            cert_fingerprint=cert_fingerprint,
            use_credential_vault=False,  # We have direct credentials
        )


class VirtualminAPIError(Exception):
    """Base exception for Virtualmin API errors"""

    def __init__(self, message: str, server: str = "", program: str = "", http_status: int = 0):
        super().__init__(message)
        self.server = server
        self.program = program
        self.http_status = http_status


class VirtualminAuthError(VirtualminAPIError):
    """Authentication failed - check credentials or ACL permissions"""


class VirtualminRateLimitedError(VirtualminAPIError):
    """Rate limit exceeded - implement exponential backoff"""


class VirtualminConflictExistsError(VirtualminAPIError):
    """Resource already exists - handle idempotently"""


class VirtualminNotFoundError(VirtualminAPIError):
    """Resource not found - domain/user/database doesn't exist"""


class VirtualminTransientError(VirtualminAPIError):
    """Temporary failure - retry with backoff"""


class VirtualminQuotaExceededError(VirtualminAPIError):
    """Server quota exceeded - try different server"""


class VirtualminResponseParser:
    """
    Handles Virtualmin's varied response formats: JSON/XML/text

    Virtualmin API can return different formats based on the request.
    This parser normalizes all responses to a consistent format.
    """

    @staticmethod
    def parse_response(response_text: str, program: str) -> dict[str, Any]:
        """
        Parse Virtualmin API response to normalized format.

        Args:
            response_text: Raw response from Virtualmin API
            program: Virtualmin program that was called

        Returns:
            Normalized response dictionary

        Raises:
            VirtualminAPIError: If response cannot be parsed
        """
        if not response_text:
            return {"success": False, "error": "Empty response"}

        # Try JSON first (preferred format)
        if response_text.strip().startswith("{"):
            try:
                data = json.loads(response_text)
                return VirtualminResponseParser._normalize_json_response(data)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON response for {program}: {e}")

        # Try XML format
        if response_text.strip().startswith("<"):
            return VirtualminResponseParser._parse_xml_response(response_text)

        # Fall back to text format parsing
        return VirtualminResponseParser._parse_text_response(response_text, program)

    @staticmethod
    def _normalize_json_response(data: dict[str, Any]) -> dict[str, Any]:
        """Normalize JSON response to standard format"""
        if isinstance(data, dict):
            # Check for common success indicators
            success = data.get("status") == "success" or data.get("success") is True or "error" not in data

            return {
                "success": success,
                "data": data,
                "error": data.get("error", ""),
                "message": data.get("message", ""),
            }

        return {"success": False, "error": "Invalid JSON structure", "data": data}  # type: ignore[unreachable]

    @staticmethod
    def _parse_xml_response(response_text: str) -> dict[str, Any]:
        """Parse XML response format"""
        # For now, treat XML as success if no obvious error
        if "error" in response_text.lower() or "failed" in response_text.lower():
            return {"success": False, "error": "XML response indicates error", "data": {}}

        return {"success": True, "data": {"xml_response": response_text}, "error": ""}

    @staticmethod
    def _parse_text_response(response_text: str, program: str) -> dict[str, Any]:
        """Parse plain text response format"""
        lines = response_text.strip().split("\n")

        # Check for common error patterns
        error_patterns = ["error:", "failed:", "not found", "permission denied", "invalid", "unauthorized", "forbidden"]

        for line in lines:
            line_lower = line.lower()
            for pattern in error_patterns:
                if pattern in line_lower:
                    return {"success": False, "error": line.strip(), "data": {"raw_response": response_text}}

        # Check for success patterns
        success_patterns = ["successfully", "completed", "created", "deleted", "modified"]

        has_success = any(pattern in response_text.lower() for pattern in success_patterns)

        # Special handling for list commands
        if program.startswith("list-"):
            # List commands are successful if they return data or empty list
            return {"success": True, "data": {"items": lines, "raw_response": response_text}, "error": ""}

        return {
            "success": has_success,
            "data": {"raw_response": response_text},
            "error": "" if has_success else "Unknown response format",
        }


class VirtualminGateway:
    """
    Production-ready Virtualmin gateway with enterprise patterns.

    🚨 NEW: Multi-path authentication + Credential Vault integration

    Features:
    - Credential Vault integration for secure credential management
    - Multi-path authentication (ACL -> Master -> SSH+sudo)
    - Comprehensive error taxonomy and handling
    - Rate limiting and circuit breaker patterns
    - Response normalization across formats
    - SSL certificate verification and pinning
    - Correlation ID tracking for observability
    - Automatic credential rotation support
    """

    def __init__(self, config: VirtualminConfig):
        self.config = config
        self.server = config.server
        self._session = self._create_session()
        self._auth_manager = None
        self._credential_vault = None

    def _get_auth_manager(self) -> VirtualminAuthenticationManager:
        """Lazy load authentication manager"""
        if not self._auth_manager:
            # Import here to avoid circular imports
            from .virtualmin_auth_manager import VirtualminAuthenticationManager  # noqa: PLC0415

            self._auth_manager = VirtualminAuthenticationManager(self.server)  # type: ignore[assignment]
        return self._auth_manager  # type: ignore[return-value]

    def _get_credential_vault(self) -> CredentialVault:
        """Lazy load credential vault"""
        if not self._credential_vault:
            from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415

            self._credential_vault = get_credential_vault()  # type: ignore[assignment]
        return self._credential_vault  # type: ignore[return-value]

    def _get_credentials(self, reason: str = "Virtualmin API call") -> Result[tuple[str, str], str]:
        """
        Get credentials using vault-first approach with environment fallback.

        Implements the migration strategy from virtualmin_review.md:
        1. Try credential vault first (new approach)
        2. Fall back to environment variables (current approach)
        3. Log which method was used for migration tracking
        """

        # Try credential vault first if enabled
        vault = self._get_credential_vault()
        if vault:
            vault_result = vault.get_credential(
                service_type="virtualmin", service_identifier=self.server.hostname, reason=reason
            )

            if vault_result.is_ok():
                credentials_data = vault_result.unwrap()
                username = credentials_data.get("username")  # type: ignore[union-attr]
                password = credentials_data.get("password")  # type: ignore[union-attr]
                if username and password:
                    logger.debug(f"🔐 [Virtualmin Gateway] Using vault credentials for {self.server.hostname}")
                    return Ok((username, password))
            else:
                logger.warning(
                    f"⚠️ [Virtualmin Gateway] Vault failed for {self.server.hostname}: {vault_result.unwrap_err()}"
                )

        # Fall back to environment variables (current migration approach)
        try:
            # Try server-specific credentials first
            if hasattr(self.server, "api_username") and hasattr(self.server, "get_api_password"):
                username = self.server.api_username
                password = self.server.get_api_password()

                if username and password:
                    logger.debug(f"🔐 [Virtualmin Gateway] Using server credentials for {self.server.hostname}")
                    return Ok((username, password))

            # Fall back to global environment variables
            env_username = os.environ.get("VIRTUALMIN_ADMIN_USER")
            env_password = os.environ.get("VIRTUALMIN_ADMIN_PASSWORD")

            if env_username and env_password:
                logger.info(
                    f"🔐 [Virtualmin Gateway] Using environment credentials for {self.server.hostname} (migration needed)"
                )
                return Ok((env_username, env_password))

            return Err("No valid credentials found in vault, server config, or environment")

        except Exception as e:
            logger.error(f"🔥 [Virtualmin Gateway] Credential retrieval failed: {e}")
            return Err(f"Credential retrieval error: {e}")

    def call_with_auth_fallback(
        self, program: str, parameters: dict[str, Any] | None = None, use_fallback_auth: bool = True
    ) -> Result[dict[str, Any], str]:
        """
        Call Virtualmin API with credential vault integration and multi-path authentication.

        Args:
            program: Virtualmin program to execute
            parameters: Command parameters
            use_fallback_auth: Whether to use authentication fallback

        Returns:
            Result with API response or error
        """
        if use_fallback_auth:
            # Use multi-path authentication manager
            return self._get_auth_manager().execute_virtualmin_command(program, parameters or {})  # type: ignore[return-value]
        else:
            # Use direct API call (legacy path)
            return self._call_direct_api(program, parameters or {})

    def _call_direct_api(self, program: str, parameters: dict[str, Any]) -> Result[dict[str, Any], str]:
        """Direct API call without authentication fallback (legacy method)"""
        raise NotImplementedError("Direct API call not implemented")

    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()

        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=VIRTUALMIN_CONNECTION_POOL_SIZE,
            pool_maxsize=VIRTUALMIN_CONNECTION_POOL_SIZE,
            max_retries=0,  # Handle retries manually
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set authentication
        session.auth = (self.server.api_username, self.server.get_api_password())

        # Configure headers
        site_url = getattr(settings, "SITE_URL", "https://pragmatichost.com")
        session.headers.update(
            {
                "User-Agent": f"PRAHO-Platform/1.0 (+{site_url})",
                "Accept": "application/json, application/xml, text/plain",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        return session

    def _check_rate_limit(self, operation: str) -> bool:
        """Check if server is within rate limits"""
        cache_key = f"virtualmin_rate_limit:{self.server.hostname}:{operation}"
        current_calls = cache.get(cache_key, 0)

        if current_calls >= VIRTUALMIN_RATE_LIMIT_MAX_CALLS:
            logger.warning(
                f"Rate limit exceeded for {self.server.hostname} operation {operation}: "
                f"{current_calls}/{VIRTUALMIN_RATE_LIMIT_MAX_CALLS}"
            )
            return False

        # Increment counter
        cache.set(cache_key, current_calls + 1, VIRTUALMIN_RATE_LIMIT_WINDOW)
        return True

    def _validate_server_health(self) -> Result[bool, str]:
        """Validate server health before making requests"""
        # Only check if server is active, not if it's healthy
        # (is_healthy depends on recent health checks, creating a catch-22)
        if self.server.status != "active":
            return Err(f"Server {self.server.hostname} is not active (status: {self.server.status})")

        return Ok(True)

    def _validate_ssl_certificate(self, response: requests.Response) -> bool:
        """Validate SSL certificate if fingerprint is configured"""
        if not self.config.cert_fingerprint:
            return True

        try:
            # Get certificate from response
            cert_der = response.raw.connection.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            cert_sha256 = hashlib.sha256(cert_der).hexdigest()

            expected = self.config.cert_fingerprint.replace("sha256:", "").lower()
            actual = cert_sha256.lower()

            if expected != actual:
                logger.error(
                    f"SSL certificate mismatch for {self.server.hostname}. Expected: {expected}, Got: {actual}"
                )
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to validate SSL certificate: {e}")
            return False

    def call(
        self,
        program: str,
        params: dict[str, Any] | None = None,
        response_format: str = "json",
        correlation_id: str = "",
    ) -> Result[VirtualminResponse, VirtualminAPIError]:
        """
        Make authenticated call to Virtualmin API.

        Args:
            program: Virtualmin program to call (e.g., 'create-domain')
            params: Parameters for the API call
            response_format: Response format ('json', 'xml', 'text')
            correlation_id: Correlation ID for request tracking

        Returns:
            Result containing VirtualminResponse or error
        """
        start_time = time.time()

        # Input validation
        try:
            program = VirtualminValidator.validate_virtualmin_program(program)
            response_format = VirtualminValidator.validate_api_response_format(response_format)

            params = VirtualminValidator.validate_virtualmin_params(params) if params else {}

        except ValidationError as e:
            return Err(VirtualminAPIError(f"Validation error: {e}", self.server.hostname, program))

        # Server health check
        health_result = self._validate_server_health()
        if health_result.is_err():
            return Err(VirtualminAPIError(health_result.unwrap_err(), self.server.hostname, program))

        # Rate limiting check
        if not self._check_rate_limit(program):
            return Err(VirtualminRateLimitedError(f"Rate limit exceeded for {program}", self.server.hostname, program))

        # Prepare request parameters
        api_params = {"program": program, **params}

        # Add response format
        if response_format == "json":
            api_params["json"] = "1"
        elif response_format == "xml":
            api_params["xml"] = "1"

        # Note: correlation_id is used for internal tracking only, not passed to Virtualmin

        logger.info(
            f"🔗 [Virtualmin] Calling {program} on {self.server.hostname}"
            f"{f' (correlation: {correlation_id})' if correlation_id else ''}"
        )

        # Make API request with retries
        last_error = None
        for attempt in range(VIRTUALMIN_MAX_RETRIES):
            try:
                response = self._make_request(api_params, attempt + 1)
                execution_time = time.time() - start_time

                # Parse response
                parsed_data = VirtualminResponseParser.parse_response(response.text, program)

                # Create normalized response
                virtualmin_response = VirtualminResponse(
                    success=parsed_data["success"],
                    data=parsed_data.get("data", {}),
                    raw_response=response.text[:10000],  # Limit logged response size
                    http_status=response.status_code,
                    execution_time=execution_time,
                    program=program,
                    server_hostname=self.server.hostname,
                )

                # Log successful response
                logger.info(
                    f"✅ [Virtualmin] {program} completed in {execution_time:.2f}s (status: {response.status_code})"
                )

                return Ok(virtualmin_response)

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(f"⚠️ [Virtualmin] Attempt {attempt + 1}/{VIRTUALMIN_MAX_RETRIES} failed: {e}")

                # Exponential backoff for retries
                if attempt < VIRTUALMIN_MAX_RETRIES - 1:
                    backoff_seconds = (2**attempt) * 0.5
                    time.sleep(backoff_seconds)

        # All retries failed
        execution_time = time.time() - start_time
        error_msg = f"All {VIRTUALMIN_MAX_RETRIES} attempts failed. Last error: {last_error}"

        logger.error(f"❌ [Virtualmin] {program} failed after {execution_time:.2f}s: {error_msg}")

        return Err(VirtualminTransientError(error_msg, self.server.hostname, program))

    def _make_request(self, params: dict[str, Any], attempt: int) -> requests.Response:
        """
        Make HTTP request to Virtualmin API.

        Args:
            params: Request parameters
            attempt: Current attempt number

        Returns:
            HTTP response object

        Raises:
            requests.RequestException: On HTTP errors
            VirtualminAPIError: On API-specific errors
        """
        try:
            response = self._execute_http_request(params)
            self._validate_response_size(response)
            self._validate_ssl_if_configured(response)
            self._validate_http_status(response)
            return response

        except requests.exceptions.ConnectTimeout as e:
            raise VirtualminTransientError(f"Connection timeout to {self.server.hostname}", self.server.hostname) from e
        except requests.exceptions.ReadTimeout as e:
            raise VirtualminTransientError(f"Read timeout from {self.server.hostname}", self.server.hostname) from e
        except requests.exceptions.ConnectionError as e:
            raise VirtualminTransientError(
                f"Connection error to {self.server.hostname}: {e}", self.server.hostname
            ) from e
        except requests.exceptions.SSLError as e:
            raise VirtualminAPIError(
                f"SSL error connecting to {self.server.hostname}: {e}", self.server.hostname
            ) from e

    def _execute_http_request(self, params: dict[str, Any]) -> requests.Response:
        """Execute the HTTP request and return response."""
        return self._session.get(
            self.server.api_url,
            params=params,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
            stream=True,  # For response size checking
        )

    def _validate_response_size(self, response: requests.Response) -> None:
        """Validate response size and read content with size limits."""
        # Check response size
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_SIZE_BYTES:
            raise VirtualminAPIError(f"Response too large: {content_length} bytes", self.server.hostname)

        # Read response with size limit
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_RESPONSE_SIZE_BYTES:
                raise VirtualminAPIError(f"Response exceeds size limit: {MAX_RESPONSE_SIZE_MB}MB", self.server.hostname)

        # Replace response content
        response._content = content

    def _validate_ssl_if_configured(self, response: requests.Response) -> None:
        """Validate SSL certificate if configured."""
        if self.server.use_ssl and self.config.cert_fingerprint and not self._validate_ssl_certificate(response):
            raise VirtualminAPIError("SSL certificate validation failed", self.server.hostname)

    def _validate_http_status(self, response: requests.Response) -> None:
        """Validate HTTP status codes and raise appropriate errors."""
        if response.status_code == HTTP_UNAUTHORIZED:
            raise VirtualminAuthError("Authentication failed - check API credentials", self.server.hostname)
        elif response.status_code == HTTP_FORBIDDEN:
            raise VirtualminAuthError("Access forbidden - check ACL permissions", self.server.hostname)
        elif response.status_code == HTTP_TOO_MANY_REQUESTS:
            raise VirtualminRateLimitedError("Server rate limit exceeded", self.server.hostname)
        elif response.status_code >= HTTP_INTERNAL_SERVER_ERROR:
            raise VirtualminTransientError(
                f"Server error: HTTP {response.status_code}", self.server.hostname, http_status=response.status_code
            )
        elif response.status_code >= HTTP_BAD_REQUEST:
            raise VirtualminAPIError(
                f"Client error: HTTP {response.status_code}", self.server.hostname, http_status=response.status_code
            )

    def test_connection(self) -> Result[dict[str, Any], str]:
        """
        Test connection to Virtualmin server.

        Returns:
            Result with connection info or error message
        """
        try:
            result = self.call("info", correlation_id=f"health_check_{int(time.time())}")

            if result.is_ok():
                response = result.unwrap()
                return Ok(
                    {
                        "healthy": response.success,
                        "response_time": response.execution_time,
                        "server": response.server_hostname,
                        "data": response.data,
                    }
                )
            else:
                error = result.unwrap_err()
                return Err(f"Connection test failed: {error}")

        except Exception as e:
            return Err(f"Connection test error: {e}")

    def get_server_info(self) -> Result[dict[str, Any], str]:
        """Get server information and statistics"""
        result = self.call("info")

        if result.is_ok():
            response = result.unwrap()
            if response.success:
                return Ok(response.data)
            else:
                return Err(f"Failed to get server info: {response.data.get('error', 'Unknown error')}")
        else:
            return Err(f"API call failed: {result.unwrap_err()}")

    def list_domains(self, name_only: bool = False) -> Result[list[dict[str, Any]], str]:
        """
        List all domains on the server.

        Args:
            name_only: Return only domain names (faster)

        Returns:
            Result with list of domains or error
        """
        # Don't use name-only parameter as it's not supported by this Virtualmin version
        result = self.call("list-domains", {})

        if result.is_ok():
            response = result.unwrap()
            if response.success:
                domains = self._parse_domains_response(response.data, name_only)
                return Ok(domains)
            else:
                return Err(f"Failed to list domains: {response.data.get('error', 'Unknown error')}")
        else:
            return Err(f"API call failed: {result.unwrap_err()}")

    def _parse_domains_response(self, data: dict[str, Any], name_only: bool) -> list[dict[str, Any]]:
        """Parse domains response based on different formats"""
        if not isinstance(data, dict):
            return []  # type: ignore[unreachable]

        # Handle different response formats
        if "domains" in data:
            return data["domains"]  # type: ignore[no-any-return]
        elif "data" in data:
            return self._parse_table_format_domains(data["data"], name_only)
        elif "items" in data:
            return data["items"]  # type: ignore[no-any-return]
        else:
            return self._parse_raw_response_domains(data)  # type: ignore[return-value]

    def _parse_table_format_domains(self, data_items: list[dict[str, Any]], name_only: bool) -> list[dict[str, Any]]:
        """Parse Virtualmin's table-like response format"""
        domains = []
        for item in data_items:
            if isinstance(item, dict) and "name" in item:
                domain_line = item["name"].strip()
                # Skip header and separator lines
                if domain_line.startswith(("Domain", "---")) or not domain_line:
                    continue

                # Parse domain info from the formatted line
                parts = domain_line.split()
                if parts and len(parts) >= DOMAIN_PARTS_MIN:
                    domain_name = parts[0]
                    username = parts[DOMAIN_USERNAME_INDEX] if len(parts) > DOMAIN_USERNAME_INDEX else ""
                    description = (
                        " ".join(parts[DOMAIN_DESCRIPTION_INDEX:]) if len(parts) > DOMAIN_DESCRIPTION_INDEX else ""
                    )

                    if name_only:
                        domains.append(domain_name)
                    else:
                        domains.append({"domain": domain_name, "username": username, "description": description})
        return domains

    def _parse_raw_response_domains(self, data: dict[str, Any]) -> list[str]:
        """Parse raw response for domain names"""
        raw_response = data.get("raw_response", "")
        if raw_response:
            return [line.strip() for line in raw_response.split("\n") if line.strip()]
        return []

    def ping_server(self) -> bool:
        """Ping server to check connectivity"""
        # Use test_connection method as ping
        result = self.test_connection()
        return result.is_ok()

    def call_api(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Generic API call method"""
        # TODO: Implement generic API call
        return {"status": "ok", "command": command}

    def get_domain_info(self, domain: str) -> Result[dict[str, Any], str]:
        """
        Get detailed domain information including usage statistics.
        
        Uses list-domains with multiline=1 for disk usage and list-bandwidth for bandwidth usage.
        
        Args:
            domain: Domain name to get information for
            
        Returns:
            Result with domain information or error message
        """
        domain_info = {
            "disk_usage_mb": 0,
            "bandwidth_usage_mb": 0,
            "disk_quota_mb": None,
            "bandwidth_quota_mb": None,
        }
        
        # Get disk usage with list-domains --multiline
        disk_result = self.call("list-domains", {"domain": domain, "multiline": ""})
        
        if disk_result.is_ok():
            response = disk_result.unwrap()
            if response.success:
                disk_info = self._parse_multiline_domain_response(response.data)
                domain_info["disk_usage_mb"] = disk_info.get("disk_usage_mb", 0)
                domain_info["disk_quota_mb"] = disk_info.get("disk_quota_mb")
            else:
                return Err(f"Failed to get disk usage: {response.data.get('error', 'Unknown error')}")
        else:
            return Err(f"Disk usage API call failed: {disk_result.unwrap_err()}")
        
        # Try to get bandwidth usage - multiple approaches
        bandwidth_found = False
        
        # 1. Try list-bandwidth command for current month (may not be allowed)
        if not bandwidth_found:
            try:
                from datetime import datetime
                current_date = datetime.now()
                start_date = current_date.replace(day=1).strftime("%Y-%m-%d")
                end_date = current_date.strftime("%Y-%m-%d")
                
                bandwidth_result = self.call("list-bandwidth", {
                    "domain": domain,
                    "start": start_date,
                    "end": end_date
                })
                
                if bandwidth_result.is_ok():
                    response = bandwidth_result.unwrap()
                    if response.success:
                        bandwidth_usage = self._parse_bandwidth_response(response.data)
                        if bandwidth_usage > 0:
                            domain_info["bandwidth_usage_mb"] = bandwidth_usage
                            bandwidth_found = True
            except Exception:
                pass
        
        # 2. Try to extract bandwidth from domain info if available
        if not bandwidth_found and disk_result.is_ok():
            response = disk_result.unwrap()
            if response.success:
                bandwidth_info = self._extract_bandwidth_from_domain_data(response.data)
                if bandwidth_info > 0:
                    domain_info["bandwidth_usage_mb"] = bandwidth_info
                    
                # Also extract bandwidth quota information
                bandwidth_quota = self._extract_bandwidth_quota_from_domain_data(response.data)
                if bandwidth_quota != 0:  # Include -1 for unlimited and positive values
                    domain_info["bandwidth_quota_mb"] = bandwidth_quota
            
        return Ok(domain_info)
    
    def _extract_bandwidth_from_domain_data(self, data: dict[str, Any]) -> int:
        """Extract bandwidth usage from domain data if available."""
        bandwidth_mb = 0
        
        if isinstance(data, dict) and 'data' in data:
            for domain_item in data['data']:
                if 'values' in domain_item:
                    values = domain_item['values']
                    
                    # Look for bandwidth-related fields (usage and quotas)
                    for key, value in values.items():
                        key_lower = key.lower()
                        value_str = value[0] if isinstance(value, list) and value else str(value)
                        
                        # Check for bandwidth usage fields
                        if any(term in key_lower for term in ['bandwidth', 'traffic', 'transfer']):
                            if 'size' in key_lower or 'usage' in key_lower or 'used' in key_lower:
                                try:
                                    bandwidth_mb = self._parse_size_to_mb(value_str)
                                    if bandwidth_mb > 0:
                                        break
                                except ValueError:
                                    continue
                    
                    if bandwidth_mb > 0:
                        break
                    
        return bandwidth_mb

    def _extract_bandwidth_quota_from_domain_data(self, data: dict[str, Any]) -> int:
        """Extract bandwidth quota from domain data."""
        quota_mb = 0
        
        if isinstance(data, dict) and 'data' in data:
            for domain_item in data['data']:
                if 'values' in domain_item:
                    values = domain_item['values']
                    
                    # Look for bandwidth quota fields
                    for key, value in values.items():
                        key_lower = key.lower()
                        
                        # Check for bandwidth limit/quota fields
                        if 'bandwidth' in key_lower and ('limit' in key_lower or 'quota' in key_lower):
                            value_str = value[0] if isinstance(value, list) and value else str(value)
                            try:
                                # Handle "Unlimited" case
                                if value_str.lower() == "unlimited":
                                    quota_mb = -1  # Use -1 to represent unlimited
                                    break
                                # Handle both regular size format and byte format
                                elif 'byte' in key_lower:
                                    # Convert bytes to MB
                                    quota_mb = int(value_str) // (1024 * 1024)
                                else:
                                    quota_mb = self._parse_size_to_mb(value_str)
                                
                                if quota_mb > 0:
                                    break
                            except (ValueError, TypeError):
                                continue
                    
                    if quota_mb > 0:
                        break
                    
        return quota_mb

    def _extract_usage_from_domain_data(self, domain_data: dict[str, Any]) -> dict[str, Any]:
        """Extract usage information from domain data returned by list-domains."""
        domain_info = {
            "disk_usage_mb": 0,
            "bandwidth_usage_mb": 0,
            "disk_quota_mb": None,
            "bandwidth_quota_mb": None,
        }
        
        # Extract disk usage if available
        if "disk_usage" in domain_data:
            domain_info["disk_usage_mb"] = self._parse_size_to_mb(domain_data["disk_usage"])
        elif "used" in domain_data:
            domain_info["disk_usage_mb"] = self._parse_size_to_mb(domain_data["used"])
            
        # Extract disk quota if available  
        if "disk_quota" in domain_data:
            domain_info["disk_quota_mb"] = self._parse_size_to_mb(domain_data["disk_quota"])
        elif "quota" in domain_data:
            domain_info["disk_quota_mb"] = self._parse_size_to_mb(domain_data["quota"])
            
        # Extract bandwidth usage if available
        if "bandwidth_usage" in domain_data:
            domain_info["bandwidth_usage_mb"] = self._parse_size_to_mb(domain_data["bandwidth_usage"])
        elif "bw_used" in domain_data:
            domain_info["bandwidth_usage_mb"] = self._parse_size_to_mb(domain_data["bw_used"])
            
        # Extract bandwidth quota if available
        if "bandwidth_quota" in domain_data:
            domain_info["bandwidth_quota_mb"] = self._parse_size_to_mb(domain_data["bandwidth_quota"])
        elif "bw_limit" in domain_data:
            domain_info["bandwidth_quota_mb"] = self._parse_size_to_mb(domain_data["bw_limit"])
        
        return domain_info

    def _parse_multiline_domain_response(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse multiline domain response to extract disk usage and quota."""
        domain_info = {
            "disk_usage_mb": 0,
            "disk_quota_mb": None,
        }
        
        # The response comes as a nested dict structure with domain data
        if isinstance(data, dict) and 'data' in data:
            for domain_item in data['data']:
                if 'values' in domain_item:
                    values = domain_item['values']
                    
                    # Try multiple sources for disk usage in priority order
                    disk_usage_found = False
                    
                    # 1. Look for database size first (most common indicator)
                    if not disk_usage_found and 'databases_size' in values:
                        size_str = values['databases_size'][0] if isinstance(values['databases_size'], list) else values['databases_size']
                        try:
                            usage_mb = self._parse_size_to_mb(size_str)
                            if usage_mb > 0:  # Only use if non-zero
                                domain_info["disk_usage_mb"] = usage_mb
                                disk_usage_found = True
                        except ValueError:
                            pass
                    
                    # 2. Look for home directory size
                    if not disk_usage_found and 'home_directory_size' in values:
                        size_str = values['home_directory_size'][0] if isinstance(values['home_directory_size'], list) else values['home_directory_size']
                        try:
                            domain_info["disk_usage_mb"] = self._parse_size_to_mb(size_str)
                            disk_usage_found = True
                        except ValueError:
                            pass
                    
                    # 3. Look for any disk-related fields
                    if not disk_usage_found:
                        for key, value in values.items():
                            key_lower = key.lower()
                            if 'size' in key_lower and 'byte' not in key_lower:  # Avoid byte_size duplicates
                                value_str = value[0] if isinstance(value, list) and value else str(value)
                                try:
                                    usage_mb = self._parse_size_to_mb(value_str)
                                    if usage_mb > 0:  # Only use if non-zero
                                        domain_info["disk_usage_mb"] = usage_mb
                                        disk_usage_found = True
                                        break
                                except ValueError:
                                    continue
                    
                    # 4. Look for quota information
                    for key, value in values.items():
                        key_lower = key.lower()
                        value_str = value[0] if isinstance(value, list) and value else str(value)
                        
                        if any(term in key_lower for term in ["quota", "limit"]) and 'size' in key_lower:
                            try:
                                domain_info["disk_quota_mb"] = self._parse_size_to_mb(value_str)
                                break
                            except ValueError:
                                continue
                    
                    break  # Only process first domain
        
        return domain_info
    
    def _parse_bandwidth_response(self, data: dict[str, Any]) -> int:
        """Parse bandwidth response to extract total usage in MB."""
        # The bandwidth response is typically CSV format or structured data
        total_mb = 0
        
        if isinstance(data, str):
            # Parse CSV-like response
            lines = data.strip().split('\n')
            for line in lines:
                if line and not line.startswith('#'):  # Skip comments
                    # Try to extract bandwidth values from the line
                    parts = line.split(',')
                    if len(parts) > 1:
                        # Usually the bandwidth is in the last column
                        try:
                            bandwidth_str = parts[-1].strip()
                            total_mb += self._parse_size_to_mb(bandwidth_str)
                        except (ValueError, IndexError):
                            continue
        elif isinstance(data, dict):
            # Handle structured response
            for key, value in data.items():
                if "bandwidth" in key.lower() or "bytes" in key.lower():
                    try:
                        total_mb += self._parse_size_to_mb(str(value))
                    except ValueError:
                        continue
        
        return total_mb

    def _parse_domain_info_response(self, data: dict[str, Any], domain: str) -> dict[str, Any]:
        """Parse domain info response to extract usage data"""
        domain_info = {
            "domain": domain,
            "disk_usage_mb": 0,
            "bandwidth_usage_mb": 0,
            "disk_quota_mb": None,
            "bandwidth_quota_mb": None,
            "status": "unknown"
        }
        
        # Handle different response formats that Virtualmin might return
        if isinstance(data, dict):
            # Look for common fields that Virtualmin returns
            if "data" in data and isinstance(data["data"], list):
                for item in data["data"]:
                    if isinstance(item, dict):
                        name = item.get("name", "").lower()
                        value = item.get("value", "")
                        
                        # Parse disk usage/quota
                        if "disk" in name and "used" in name:
                            domain_info["disk_usage_mb"] = self._parse_size_to_mb(value)
                        elif "disk" in name and ("quota" in name or "limit" in name):
                            domain_info["disk_quota_mb"] = self._parse_size_to_mb(value)
                        
                        # Parse bandwidth usage/quota
                        elif "bandwidth" in name and "used" in name:
                            domain_info["bandwidth_usage_mb"] = self._parse_size_to_mb(value)
                        elif "bandwidth" in name and ("quota" in name or "limit" in name):
                            domain_info["bandwidth_quota_mb"] = self._parse_size_to_mb(value)
                        
                        # Parse status
                        elif "status" in name:
                            domain_info["status"] = value.lower()
                            
        return domain_info
    
    def _parse_size_to_mb(self, size_str: str) -> int:
        """Convert size string to MB (e.g., '500M', '1.2G', '1024K')"""
        if not size_str or size_str == "-" or size_str.lower() == "unlimited":
            return 0
            
        size_str = str(size_str).strip().upper()
        
        try:
            # Extract number and unit
            import re
            match = re.match(r'([0-9.]+)\s*([KMGT]?)B?', size_str)
            if match:
                number = float(match.group(1))
                unit = match.group(2)
                
                # Convert to MB
                if unit == "K":
                    return int(number / 1024)
                elif unit == "M":
                    return int(number)
                elif unit == "G":
                    return int(number * 1024)
                elif unit == "T":
                    return int(number * 1024 * 1024)
                else:
                    # Assume bytes if no unit
                    return int(number / (1024 * 1024))
            else:
                # Try to parse as plain number (assume MB)
                return int(float(size_str))
        except (ValueError, AttributeError):
            return 0

    def close(self) -> None:
        """Close the gateway and clean up resources"""
        if hasattr(self, "_session"):
            self._session.close()
