"""
MockVirtualminGateway - Stateful drop-in replacement for VirtualminGateway.

Provides realistic mock behavior for testing without network access:
- In-memory domain state tracking (create/suspend/delete)
- Realistic error responses (conflict, not-found, quota)
- Call logging for test assertions
- Configurable failure injection
- Responses pass through VirtualminResponseParser

Usage in tests:
    class MyTest(VirtualminMockMixin, TestCase):
        def test_something(self):
            self.mock_gateway.seed_domain("existing.com")
            result = self.provisioning_service.create_account(...)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

from apps.common.types import Err, Ok, Result
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConflictExistsError,
    VirtualminNotFoundError,
    VirtualminQuotaExceededError,
    VirtualminResponse,
    VirtualminResponseParser,
)
from tests.fixtures.virtualmin.responses import (
    create_domain,
    delete_domain,
    disable_domain,
    enable_domain,
    errors,
    info,
    list_bandwidth,
    list_domains,
)


@dataclass
class MockDomain:
    """In-memory representation of a Virtualmin domain."""

    name: str
    username: str = ""
    enabled: bool = True
    disk_usage_mb: int = 0
    disk_quota_mb: int = 1000
    bandwidth_usage_mb: int = 0
    bandwidth_quota_mb: int = 10000
    features: list[str] = field(default_factory=lambda: ["web", "dns", "mail", "mysql"])

    def __post_init__(self) -> None:
        if not self.username:
            self.username = self.name.split(".")[0]


@dataclass
class CallRecord:
    """Record of a single API call."""

    program: str
    params: dict[str, Any]
    timestamp: float
    result_success: bool


class MockVirtualminGateway:
    """
    Stateful mock that mimics VirtualminGateway's public interface.

    State is tracked in-memory: domains can be created, suspended, deleted.
    Responses are generated from fixture factories and parsed through
    VirtualminResponseParser so parsing bugs get caught in tests.
    """

    def __init__(
        self,
        server_hostname: str = "mock-server.example.com",
        max_domains: int = 1000,
        fail_operations: dict[str, str] | None = None,
    ) -> None:
        self.server_hostname = server_hostname
        self.max_domains = max_domains
        self.fail_operations = fail_operations or {}

        # State
        self._domains: dict[str, MockDomain] = {}
        self._calls: list[CallRecord] = []

    # ---------------------------------------------------------------
    # State management helpers (for test setup)
    # ---------------------------------------------------------------

    def seed_domain(
        self,
        domain: str,
        username: str = "",
        enabled: bool = True,
        disk_usage_mb: int = 50,
        disk_quota_mb: int = 1000,
        bandwidth_usage_mb: int = 100,
        bandwidth_quota_mb: int = 10000,
    ) -> MockDomain:
        """Pre-populate a domain in mock state. Returns the MockDomain."""
        d = MockDomain(
            name=domain,
            username=username or domain.split(".")[0],
            enabled=enabled,
            disk_usage_mb=disk_usage_mb,
            disk_quota_mb=disk_quota_mb,
            bandwidth_usage_mb=bandwidth_usage_mb,
            bandwidth_quota_mb=bandwidth_quota_mb,
        )
        self._domains[domain] = d
        return d

    def get_domain_state(self, domain: str) -> MockDomain | None:
        """Inspect mock state for assertions."""
        return self._domains.get(domain)

    @property
    def domain_count(self) -> int:
        return len(self._domains)

    # ---------------------------------------------------------------
    # Call logging
    # ---------------------------------------------------------------

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def get_calls(self, program: str | None = None) -> list[CallRecord]:
        """Get call records, optionally filtered by program."""
        if program is None:
            return list(self._calls)
        return [c for c in self._calls if c.program == program]

    def reset_calls(self) -> None:
        """Clear call history (not domain state)."""
        self._calls.clear()

    def reset(self) -> None:
        """Clear all state and call history."""
        self._domains.clear()
        self._calls.clear()

    # ---------------------------------------------------------------
    # Main API: call()
    # ---------------------------------------------------------------

    def call(
        self,
        program: str,
        params: dict[str, Any] | None = None,
        response_format: str = "json",
        correlation_id: str = "",
    ) -> Result[VirtualminResponse, VirtualminAPIError]:
        """
        Main entry point - matches VirtualminGateway.call() signature.

        Dispatches to program-specific handlers, generates fixture responses,
        parses them through VirtualminResponseParser, and wraps in VirtualminResponse.
        """
        params = params or {}
        start = time.monotonic()

        # Check for injected failures
        if program in self.fail_operations:
            error_msg = self.fail_operations[program]
            self._record_call(program, params, success=False)
            return Err(VirtualminAPIError(error_msg, self.server_hostname, program))

        # Dispatch to handler
        handler = self._get_handler(program)
        try:
            raw_response_dict = handler(params)
        except VirtualminAPIError as e:
            self._record_call(program, params, success=False)
            return Err(e)

        # Convert fixture dict to JSON string, then parse through real parser
        raw_json = json.dumps(raw_response_dict)
        parsed = VirtualminResponseParser.parse_response(raw_json, program)

        execution_time = time.monotonic() - start
        success = parsed.get("success", False)

        self._record_call(program, params, success=success)

        response = VirtualminResponse(
            success=success,
            data=parsed.get("data", {}),
            raw_response=raw_json,
            http_status=200 if success else 400,
            execution_time=execution_time,
            program=program,
            server_hostname=self.server_hostname,
        )

        if success:
            return Ok(response)
        else:
            return Ok(response)  # Non-success is still a valid API response

    # ---------------------------------------------------------------
    # High-level convenience methods (match VirtualminGateway)
    # ---------------------------------------------------------------

    def test_connection(self) -> Result[dict[str, Any], str]:
        """Test connection to mock server."""
        if "info" in self.fail_operations:
            return Err(f"Connection test failed: {self.fail_operations['info']}")

        result = self.call("info")
        if result.is_ok():
            response = result.unwrap()
            return Ok({
                "healthy": response.success,
                "response_time": response.execution_time,
                "server": response.server_hostname,
                "data": response.data,
            })
        return Err(f"Connection test failed: {result.unwrap_err()}")

    def list_domains(self, name_only: bool = False) -> Result[list[dict[str, Any]], str]:
        """List all domains in mock state."""
        result = self.call("list-domains", {})
        if result.is_ok():
            response = result.unwrap()
            if response.success:
                raw_data = response.data.get("data", [])
                if name_only:
                    return Ok([{"domain": d["name"]} for d in raw_data if isinstance(d, dict)])
                return Ok([
                    {
                        "domain": d["name"],
                        "username": d.get("values", {}).get("Username", ""),
                        "description": "",
                    }
                    for d in raw_data
                    if isinstance(d, dict)
                ])
            return Err(f"Failed to list domains: {response.data.get('error', 'Unknown')}")
        return Err(f"API call failed: {result.unwrap_err()}")

    def get_server_info(self) -> Result[dict[str, Any], str]:
        """Get mock server info."""
        result = self.call("info")
        if result.is_ok():
            response = result.unwrap()
            if response.success:
                return Ok(response.data)
            return Err(f"Failed to get server info: {response.data.get('error', 'Unknown')}")
        return Err(f"API call failed: {result.unwrap_err()}")

    def get_domain_info(self, domain: str) -> Result[dict[str, Any], str]:
        """Get domain info from mock state."""
        d = self._domains.get(domain)
        if d is None:
            return Err(f"Virtual server {domain} does not exist")

        return Ok({
            "disk_usage_mb": d.disk_usage_mb,
            "disk_quota_mb": d.disk_quota_mb,
            "bandwidth_usage_mb": d.bandwidth_usage_mb,
            "bandwidth_quota_mb": d.bandwidth_quota_mb,
        })

    def close(self) -> None:
        """No-op for mock."""

    def ping_server(self) -> bool:
        """Check if mock server is 'reachable'."""
        return "info" not in self.fail_operations

    def call_api(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Generic API call stub."""
        return {"status": "ok", "command": command}

    # ---------------------------------------------------------------
    # Program-specific handlers
    # ---------------------------------------------------------------

    def _get_handler(self, program: str) -> Any:
        handlers: dict[str, Any] = {
            "create-domain": self._handle_create_domain,
            "delete-domain": self._handle_delete_domain,
            "disable-domain": self._handle_disable_domain,
            "enable-domain": self._handle_enable_domain,
            "list-domains": self._handle_list_domains,
            "list-bandwidth": self._handle_list_bandwidth,
            "info": self._handle_info,
            "modify-domain": self._handle_modify_domain,
        }
        handler = handlers.get(program, self._handle_generic_success)
        return handler

    def _handle_create_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            return errors.generic("create-domain", "No domain name specified")

        if domain in self._domains:
            raise VirtualminConflictExistsError(
                f"Virtual server {domain} already exists",
                self.server_hostname,
                "create-domain",
            )

        if len(self._domains) >= self.max_domains:
            raise VirtualminQuotaExceededError(
                f"Cannot create virtual server {domain} - server quota exceeded",
                self.server_hostname,
                "create-domain",
            )

        username = params.get("user", domain.split(".")[0])
        self._domains[domain] = MockDomain(name=domain, username=username)
        return create_domain.success(domain=domain, username=username)

    def _handle_delete_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if domain not in self._domains:
            raise VirtualminNotFoundError(
                f"Virtual server {domain} does not exist",
                self.server_hostname,
                "delete-domain",
            )

        del self._domains[domain]
        return delete_domain.success(domain=domain)

    def _handle_disable_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        d = self._domains.get(domain)
        if d is None:
            raise VirtualminNotFoundError(
                f"Virtual server {domain} does not exist",
                self.server_hostname,
                "disable-domain",
            )

        if not d.enabled:
            return disable_domain.already_disabled(domain=domain)

        d.enabled = False
        return disable_domain.success(domain=domain)

    def _handle_enable_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        d = self._domains.get(domain)
        if d is None:
            raise VirtualminNotFoundError(
                f"Virtual server {domain} does not exist",
                self.server_hostname,
                "enable-domain",
            )

        if d.enabled:
            return enable_domain.already_enabled(domain=domain)

        d.enabled = True
        return enable_domain.success(domain=domain)

    def _handle_list_domains(self, params: dict[str, Any]) -> dict[str, Any]:
        filter_domain = params.get("domain")
        is_multiline = "multiline" in params

        if filter_domain:
            d = self._domains.get(filter_domain)
            if d is None:
                return list_domains.empty()
            return list_domains.single_domain(
                domain=d.name,
                username=d.username,
                disk_usage=f"{d.disk_usage_mb} MB",
                disk_quota=f"{d.disk_quota_mb} MB",
                bandwidth_usage=f"{d.bandwidth_usage_mb} MB",
                bandwidth_quota=f"{d.bandwidth_quota_mb} MB",
            )

        domain_data = [
            {
                "name": d.name,
                "username": d.username,
                "disk_usage": f"{d.disk_usage_mb} MB",
                "disk_quota": f"{d.disk_quota_mb} MB",
                "bandwidth_usage": f"{d.bandwidth_usage_mb} MB",
                "bandwidth_quota": f"{d.bandwidth_quota_mb} MB",
                "enabled": d.enabled,
            }
            for d in self._domains.values()
        ]

        if is_multiline:
            return list_domains.multiline_response(domain_data)
        return list_domains.name_only([d.name for d in self._domains.values()])

    def _handle_list_bandwidth(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        d = self._domains.get(domain)
        if d is None:
            return list_bandwidth.empty(domain=domain)

        bytes_total = d.bandwidth_usage_mb * 1024 * 1024
        return list_bandwidth.success(
            domain=domain,
            bytes_in=bytes_total // 2,
            bytes_out=bytes_total // 2,
        )

    def _handle_info(self, params: dict[str, Any]) -> dict[str, Any]:
        return info.server_info(hostname=self.server_hostname)

    def _handle_modify_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if domain not in self._domains:
            raise VirtualminNotFoundError(
                f"Virtual server {domain} does not exist",
                self.server_hostname,
                "modify-domain",
            )
        return {
            "command": "modify-domain",
            "status": "success",
            "output": f"Domain {domain} modified successfully",
        }

    def _handle_generic_success(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "command": "unknown",
            "status": "success",
            "output": "Operation completed successfully",
        }

    # ---------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------

    def _record_call(self, program: str, params: dict[str, Any], *, success: bool) -> None:
        self._calls.append(CallRecord(
            program=program,
            params=dict(params),
            timestamp=time.monotonic(),
            result_success=success,
        ))


class VirtualminMockMixin:
    """
    Mixin for Django TestCase that patches VirtualminGateway with MockVirtualminGateway.

    Usage:
        class MyTest(VirtualminMockMixin, TestCase):
            def test_create(self):
                self.mock_gateway.seed_domain("existing.com")
                # ... test code that uses VirtualminProvisioningService ...

    The mixin patches 'apps.provisioning.virtualmin_service.VirtualminGateway'
    so that any service code creating a gateway gets the mock instead.
    """

    mock_gateway: MockVirtualminGateway
    _gateway_patcher: Any

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
        self.mock_gateway = MockVirtualminGateway()
        self._gateway_patcher = patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=self.mock_gateway,
        )
        self._gateway_patcher.start()

    def tearDown(self) -> None:
        self._gateway_patcher.stop()
        super().tearDown()  # type: ignore[misc]
