"""
Secure Server Management Gateway - PRAHO Platform
Secure API integration for server provisioning and management.
"""

import hashlib
import hmac
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import requests
from django.core.cache import cache
from django.core.exceptions import ValidationError

from apps.common.validators import SecureInputValidator

from .models import Server

logger = logging.getLogger(__name__)

# Server management API security constants
API_REQUEST_TIMEOUT = 30  # seconds
API_MAX_RETRIES = 3
API_RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
API_RATE_LIMIT_MAX_CALLS = 50  # Max API calls per hour per server
HTTP_SUCCESS_THRESHOLD = 400  # HTTP status codes below this are considered successful

# Whitelisted server management domains for SSRF protection
WHITELISTED_SERVER_MANAGEMENT_DOMAINS = [
    # Cloud providers
    "api.digitalocean.com",
    "api.vultr.com",
    "api.linode.com",
    "compute.googleapis.com",  # Google Cloud
    "ec2.amazonaws.com",  # AWS
    "management.azure.com",  # Azure
    # Control panels
    "api.virtualmin.com",
    "api.cpanel.net",
    "api.plesk.com",
    "api.cyberpanel.net",
    # Romanian hosting providers
    "api.hostinger.ro",
    "api.zap.ro",
    "api.romarg.ro",
    "api.netconcept.ro",
    # Development/testing
    "localhost",
    "127.0.0.1",
    "test.server-management.local",
]


class SecureServerGateway:
    """
    🔒 Secure server management gateway with comprehensive security

    Features:
    - SSRF protection via endpoint whitelisting
    - Rate limiting per server
    - Encrypted credential management
    - Webhook signature verification
    - Timeout and retry logic
    - Resource allocation validation
    """

    @staticmethod
    def create_service_on_server(server: Server, service_data: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """🆕 Create hosting service on server"""
        # Security validations
        if not SecureServerGateway._validate_server_endpoint(server.management_api_url):
            logger.error(f"🚨 [Server Gateway] Invalid server endpoint: {server.name}")
            return False, {"error": "Invalid server configuration"}

        # Check rate limits
        if not SecureServerGateway._check_server_rate_limit(server, "create_service"):
            logger.warning(f"⚠️ [Server Gateway] Rate limit exceeded for {server.name}")
            return False, {"error": "Rate limit exceeded"}

        # Validate service data
        if not SecureServerGateway._validate_service_creation_data(service_data):
            return False, {"error": "Invalid service configuration"}

        # Get decrypted API credentials
        api_key, api_secret = server.get_management_api_credentials()
        if not api_key:
            logger.error(f"🔥 [Server Gateway] No API credentials for {server.name}")
            return False, {"error": "Missing API credentials"}

        logger.info(f"🖥️ [Server Gateway] Creating service on {server.name}")

        # Make secure API call
        success, response = SecureServerGateway._make_secure_server_call(
            server, "POST", "/services/create", service_data
        )

        if success:
            # Log successful service creation
            logger.info(f"✅ [Server Gateway] Service created on {server.name}")
            return True, response
        else:
            logger.error(f"❌ [Server Gateway] Service creation failed on {server.name}: {response}")
            return False, response

    @staticmethod
    def suspend_service_on_server(server: Server, service_id: str, reason: str = "") -> tuple[bool, dict[str, Any]]:
        """⏸️ Suspend hosting service on server"""
        # Security validations
        if not SecureServerGateway._validate_server_endpoint(server.management_api_url):
            return False, {"error": "Invalid server configuration"}

        if not SecureServerGateway._check_server_rate_limit(server, "suspend_service"):
            return False, {"error": "Rate limit exceeded"}

        logger.info(f"🖥️ [Server Gateway] Suspending service {service_id} on {server.name}")

        # Make secure API call
        success, response = SecureServerGateway._make_secure_server_call(
            server, "POST", f"/services/{service_id}/suspend", {"reason": reason, "suspended_by": "praho_platform"}
        )

        return success, response

    @staticmethod
    def get_server_resources(server: Server) -> tuple[bool, dict[str, Any]]:
        """📊 Get server resource utilization"""
        # Security validations
        if not SecureServerGateway._validate_server_endpoint(server.management_api_url):
            return False, {"error": "Invalid server configuration"}

        if not SecureServerGateway._check_server_rate_limit(server, "get_resources"):
            return False, {"error": "Rate limit exceeded"}

        logger.info(f"📊 [Server Gateway] Getting resources for {server.name}")

        # Make secure API call
        success, response = SecureServerGateway._make_secure_server_call(server, "GET", "/server/resources", {})

        if success:
            # Update server resource metrics
            SecureServerGateway._update_server_metrics(server, response)

        return success, response

    @staticmethod
    def verify_webhook_signature(server: Server, payload: str, signature: str) -> bool:
        """🔐 Verify webhook signature from server management system"""
        if not server.management_webhook_secret or not signature:
            logger.warning(f"⚠️ [Server Webhook] Missing secret or signature for {server.name}")
            return False

        try:
            # Calculate expected signature
            webhook_secret = server.management_webhook_secret.encode("utf-8")
            expected_signature = hmac.new(webhook_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

            # Compare signatures (timing-safe comparison)
            return hmac.compare_digest(f"sha256={expected_signature}", signature)

        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Signature verification failed for {server.name}: {e}")
            return False

    @staticmethod
    def validate_resource_allocation(server: Server, resource_requirements: dict[str, Any]) -> tuple[bool, str]:
        """🎯 Validate resource allocation request"""
        try:
            error: str | None = None
            # Check CPU cores
            required_cpu = resource_requirements.get("cpu_cores", 0)
            if required_cpu > server.cpu_cores:
                error = f"Insufficient CPU cores: required {required_cpu}, available {server.cpu_cores}"

            # Check RAM
            if error is None:
                required_ram = resource_requirements.get("ram_gb", 0)
                if required_ram > server.ram_gb:
                    error = f"Insufficient RAM: required {required_ram}GB, available {server.ram_gb}GB"

            # Check disk space
            if error is None:
                required_disk = resource_requirements.get("disk_gb", 0)
                available_disk: float = float(server.disk_capacity_gb)
                if server.disk_usage_percent:
                    used_disk = (float(server.disk_usage_percent) / 100) * available_disk
                    available_disk = available_disk - used_disk
                if required_disk > available_disk:
                    error = f"Insufficient disk space: required {required_disk}GB, available {available_disk:.1f}GB"

            # Check server capacity limits
            if error is None and server.max_services and server.active_services_count >= server.max_services:
                error = f"Server at capacity: {server.active_services_count}/{server.max_services} services"

            # Check server status
            if error is None and server.status != "active":
                error = f"Server not available: status is {server.status}"

            if error is not None:
                return False, error
            return True, "Resource allocation validated successfully"

        except Exception as e:
            logger.error(f"🔥 [Resource Validation] Error validating allocation: {e}")
            return False, "Resource validation failed"

    @staticmethod
    def _validate_server_endpoint(endpoint: str) -> bool:
        """🛡️ Validate server management endpoint for SSRF protection"""
        if not endpoint:
            return False

        try:
            # Use existing SSRF validation
            SecureInputValidator.validate_safe_url(endpoint)

            # Additional server management endpoint whitelist check
            parsed = urlparse(endpoint)
            hostname = parsed.hostname

            if hostname not in WHITELISTED_SERVER_MANAGEMENT_DOMAINS:
                logger.warning(f"🚨 [SSRF] Server endpoint not whitelisted: {hostname}")
                return False

            return True

        except Exception as e:
            logger.error(f"🔥 [SSRF] Server endpoint validation failed: {e}")
            return False

    @staticmethod
    def _check_server_rate_limit(server: Server, operation: str) -> bool:
        """⏱️ Check API rate limits per server"""
        cache_key = f"server_api_limit:{server.id}:{operation}"

        try:
            # Get current call count
            current_calls = cache.get(cache_key, 0)

            if current_calls >= API_RATE_LIMIT_MAX_CALLS:
                logger.warning(
                    f"🚨 [Rate Limit] Server {server.name} exceeded limit: {current_calls}/{API_RATE_LIMIT_MAX_CALLS}"
                )
                return False

            # Increment counter
            cache.set(cache_key, current_calls + 1, timeout=API_RATE_LIMIT_WINDOW)
            return True

        except Exception as e:
            logger.error(f"🔥 [Rate Limit] Check failed for {server.name}: {e}")
            # Allow request if rate limiting fails (fail-open for availability)
            return True

    @staticmethod
    def _validate_service_creation_data(service_data: dict[str, Any]) -> bool:
        """🔍 Validate service creation data for security"""
        try:
            # Required fields
            required_fields = ["username", "domain", "plan_type"]
            for field in required_fields:
                if not service_data.get(field):
                    logger.error(f"🚨 [Validation] Missing required field: {field}")
                    return False

            # Validate username format (alphanumeric + underscore only)
            username = service_data.get("username", "")
            if not username.replace("_", "").isalnum():
                logger.error(f"🚨 [Validation] Invalid username format: {username}")
                return False

            # Validate domain format
            domain = service_data.get("domain", "")
            if not domain.replace(".", "").replace("-", "").isalnum():
                logger.error(f"🚨 [Validation] Invalid domain format: {domain}")
                return False

            # Check for malicious patterns in all string values
            for key, value in service_data.items():
                if isinstance(value, str):
                    try:
                        SecureInputValidator._check_malicious_patterns(value)
                    except ValidationError:
                        logger.error(f"🚨 [Validation] Malicious pattern detected in {key}: {value[:50]}")
                        return False

            return True

        except Exception as e:
            logger.error(f"🔥 [Validation] Service data validation failed: {e}")
            return False

    @staticmethod
    def _make_secure_server_call(
        server: Server, method: str, endpoint: str, data: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """🔒 Make secure HTTP API call to server management system"""
        full_url = f"{server.management_api_url.rstrip('/')}{endpoint}"
        api_key, api_secret = server.get_management_api_credentials()

        headers = {
            "User-Agent": "PRAHO-Platform/1.0",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Server-ID": str(server.id),
        }

        # Add API secret to headers if available
        if api_secret:
            headers["X-API-Secret"] = api_secret

        success = False
        result: dict[str, Any] = {}
        for attempt in range(API_MAX_RETRIES):
            req = {
                "method": method,
                "url": full_url,
                "json": data,
                "headers": headers,
                "timeout": API_REQUEST_TIMEOUT,
                "verify": True,
            }
            success, payload, should_continue = SecureServerGateway._attempt_request(
                request_kwargs=req,
                server_name=server.name,
                attempt=attempt,
                max_retries=API_MAX_RETRIES,
            )
            if success:
                return True, payload
            result = payload
            if not should_continue:
                break
            # Exponential backoff with cryptographically secure jitter
            jitter = secrets.randbelow(1000) / 1000  # 0-1 second jitter
            delay = (2**attempt) + jitter
            time.sleep(delay)

        if result:
            return False, result
        return False, {"error": "All retry attempts failed"}

    @staticmethod
    def _attempt_request(
        *,
        request_kwargs: dict[str, Any],
        server_name: str,
        attempt: int,
        max_retries: int,
    ) -> tuple[bool, dict[str, Any], bool]:
        """Perform a single HTTP request attempt with unified error handling.
        Returns (success, payload, should_continue).
        """
        logger.info(
            f"🖥️ [Server API] {request_kwargs.get('method')} {request_kwargs.get('url')} "
            f"(attempt {attempt + 1}/{max_retries})"
        )
        try:
            response = requests.request(
                method=request_kwargs["method"],
                url=request_kwargs["url"],
                json=request_kwargs.get("json"),
                headers=request_kwargs["headers"],
                timeout=API_REQUEST_TIMEOUT,
                verify=True,
            )
            is_success, resp_payload = SecureServerGateway._process_http_response(response)
            if is_success:
                return True, resp_payload, False
            # Failure: continue unless last attempt
            is_last = attempt == max_retries - 1
            return False, resp_payload, not is_last
        except Exception as e:  # Consolidated exception handling
            is_last = attempt == max_retries - 1
            if isinstance(e, requests.exceptions.Timeout):
                logger.warning(f"⏱️ [Server API] Timeout for {server_name} (attempt {attempt + 1})")
                payload = {"error": "Request timeout"}
            elif isinstance(e, requests.exceptions.ConnectionError):
                logger.warning(f"🔌 [Server API] Connection error for {server_name}: {e}")
                payload = {"error": "Connection failed"}
            else:
                logger.error(f"🔥 [Server API] Unexpected error for {server_name}: {e}")
                payload = {"error": str(e)}
            return False, payload, not is_last

    @staticmethod
    def _process_http_response(response: requests.Response) -> tuple[bool, dict[str, Any]]:
        """Process HTTP response into a success flag and payload."""
        if response.status_code < HTTP_SUCCESS_THRESHOLD:
            try:
                return True, response.json()
            except ValueError:
                return True, {"response": response.text}
        logger.warning(f"⚠️ [Server API] HTTP {response.status_code}: {response.text}")
        return False, {"error": f"HTTP {response.status_code}", "message": response.text[:200]}

    @staticmethod
    def _update_server_metrics(server: Server, resource_data: dict[str, Any]) -> None:
        """📊 Update server resource metrics from API response"""
        try:
            # Update CPU usage
            if "cpu_usage_percent" in resource_data:
                server.cpu_usage_percent = resource_data["cpu_usage_percent"]

            # Update RAM usage
            if "ram_usage_percent" in resource_data:
                server.ram_usage_percent = resource_data["ram_usage_percent"]

            # Update disk usage
            if "disk_usage_percent" in resource_data:
                server.disk_usage_percent = resource_data["disk_usage_percent"]

            server.save(update_fields=["cpu_usage_percent", "ram_usage_percent", "disk_usage_percent", "updated_at"])

            logger.info(f"📊 [Server Metrics] Updated metrics for {server.name}")

        except Exception as e:
            logger.error(f"🔥 [Server Metrics] Failed to update metrics for {server.name}: {e}")


class ResourceAllocationWorkflow:
    """
    🎯 Resource allocation confirmation workflow

    Provides secure resource allocation with confirmation and validation
    """

    @staticmethod
    def request_resource_allocation(
        server: Server, service_data: dict[str, Any], requested_by: str
    ) -> tuple[bool, str, dict[str, Any]]:
        """📝 Request resource allocation with validation"""
        try:
            # Extract resource requirements
            resource_requirements = {
                "cpu_cores": service_data.get("cpu_cores", 1),
                "ram_gb": service_data.get("ram_gb", 1),
                "disk_gb": service_data.get("disk_gb", 10),
            }

            # Validate resource allocation
            is_valid, message = SecureServerGateway.validate_resource_allocation(server, resource_requirements)

            if not is_valid:
                logger.warning(f"⚠️ [Resource Allocation] Validation failed: {message}")
                return False, message, {}

            # Create allocation record
            allocation_data = {
                "allocation_id": f"alloc_{secrets.token_urlsafe(16)}",
                "server_id": str(server.id),
                "server_name": server.name,
                "resource_requirements": resource_requirements,
                "requested_by": requested_by,
                "requested_at": time.time(),
                "status": "pending_confirmation",
            }

            # Store allocation request in cache for confirmation
            cache_key = f"resource_allocation:{allocation_data['allocation_id']}"
            cache.set(cache_key, allocation_data, timeout=3600)  # 1 hour expiry

            logger.info(f"🎯 [Resource Allocation] Request created: {allocation_data['allocation_id']}")

            return True, "Resource allocation request created successfully", allocation_data

        except Exception as e:
            logger.error(f"🔥 [Resource Allocation] Request failed: {e}")
            return False, "Resource allocation request failed", {}

    @staticmethod
    def confirm_resource_allocation(allocation_id: str, confirmed_by: str) -> tuple[bool, str]:
        """✅ Confirm resource allocation"""
        try:
            # Retrieve allocation request
            cache_key = f"resource_allocation:{allocation_id}"
            allocation_data = cache.get(cache_key)

            if not allocation_data:
                return False, "Allocation request not found or expired"

            # Update allocation status
            allocation_data["status"] = "confirmed"
            allocation_data["confirmed_by"] = confirmed_by
            allocation_data["confirmed_at"] = time.time()

            # Store confirmed allocation
            cache.set(cache_key, allocation_data, timeout=86400)  # 24 hours

            logger.info(f"✅ [Resource Allocation] Confirmed: {allocation_id} by {confirmed_by}")

            return True, "Resource allocation confirmed successfully"

        except Exception as e:
            logger.error(f"🔥 [Resource Allocation] Confirmation failed: {e}")
            return False, "Resource allocation confirmation failed"

    @staticmethod
    def get_allocation_status(allocation_id: str) -> tuple[bool, dict[str, Any]]:
        """📋 Get resource allocation status"""
        try:
            cache_key = f"resource_allocation:{allocation_id}"
            allocation_data = cache.get(cache_key)

            if not allocation_data:
                return False, {"error": "Allocation request not found"}

            return True, allocation_data

        except Exception as e:
            logger.error(f"🔥 [Resource Allocation] Status check failed: {e}")
            return False, {"error": "Status check failed"}
