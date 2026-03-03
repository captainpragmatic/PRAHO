"""
Cloud Provider Gateway — Abstract Base Class + Factory

Unified interface for multi-cloud server provisioning.
Each provider implements the CloudProviderGateway ABC using its native SDK.

See ADR-0027 for the migration from Terraform to SDK-based provisioning.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from apps.common.types import Result

logger = logging.getLogger(__name__)


# =============================================================================
# Unified Dataclasses — Provider-agnostic request/response types
# =============================================================================


@dataclass
class ServerCreateRequest:
    """Request to create a cloud server."""

    name: str
    server_type: str
    location: str
    ssh_keys: list[str]
    image: str = "ubuntu-22.04"
    labels: dict[str, str] = field(default_factory=dict)
    firewall_ids: list[str] = field(default_factory=list)


@dataclass
class ServerCreateResult:
    """Result of server creation."""

    server_id: str
    ipv4_address: str
    ipv6_address: str = ""
    root_password: str = ""


@dataclass
class ServerInfo:
    """Snapshot of server state from the cloud provider."""

    server_id: str
    name: str
    status: str
    ipv4_address: str
    ipv6_address: str = ""
    server_type: str = ""
    location: str = ""
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class SSHKeyResult:
    """Result of SSH key upload."""

    key_id: str
    name: str
    fingerprint: str = ""


@dataclass
class FirewallRule:
    """A single firewall rule."""

    direction: str = "in"
    protocol: str = "tcp"
    port: str = ""
    source_ips: list[str] = field(default_factory=lambda: ["0.0.0.0/0", "::/0"])
    description: str = ""


@dataclass
class ServerTypeInfo:
    """Information about an available server type/plan."""

    name: str
    description: str = ""
    vcpus: int = 0
    memory_gb: float = 0.0
    disk_gb: int = 0
    price_monthly: float = 0.0
    available: bool = True


@dataclass
class LocationInfo:
    """Information about an available datacenter location."""

    name: str
    description: str = ""
    country: str = ""
    city: str = ""


# =============================================================================
# Abstract Base Class
# =============================================================================


class CloudProviderGateway(ABC):
    """
    Abstract gateway for cloud provider operations.

    All server_id parameters use `str` for cross-provider compatibility.
    Provider implementations convert internally as needed (e.g., Hetzner uses int).
    """

    @abstractmethod
    def __init__(self, token: str, **kwargs: Any) -> None: ...

    @abstractmethod
    def create_server(self, request: ServerCreateRequest) -> Result[ServerCreateResult, str]:
        """Create a new cloud server."""

    @abstractmethod
    def delete_server(self, server_id: str) -> Result[bool, str]:
        """Delete a server by ID."""

    @abstractmethod
    def get_server(self, server_id: str) -> Result[ServerInfo | None, str]:
        """Get server info by ID. Returns None if not found."""

    @abstractmethod
    def power_on(self, server_id: str) -> Result[bool, str]:
        """Power on a server."""

    @abstractmethod
    def power_off(self, server_id: str) -> Result[bool, str]:
        """Power off a server."""

    @abstractmethod
    def reboot(self, server_id: str) -> Result[bool, str]:
        """Reboot a server."""

    @abstractmethod
    def resize(self, server_id: str, server_type: str) -> Result[bool, str]:
        """Resize a server to a new type."""

    @abstractmethod
    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKeyResult, str]:
        """Upload an SSH key. Replaces if name exists with different content."""

    @abstractmethod
    def delete_ssh_key(self, name: str) -> Result[bool, str]:
        """Delete an SSH key by name."""

    @abstractmethod
    def create_firewall(
        self, name: str, rules: list[FirewallRule], labels: dict[str, str] | None = None
    ) -> Result[str, str]:
        """Create a firewall with rules. Returns firewall ID."""

    @abstractmethod
    def delete_firewall(self, firewall_id: str) -> Result[bool, str]:
        """Delete a firewall by ID."""

    @abstractmethod
    def get_locations(self) -> Result[Sequence[LocationInfo], str]:
        """Get all available datacenter locations."""

    @abstractmethod
    def get_server_types(self) -> Result[Sequence[ServerTypeInfo], str]:
        """Get all available server types/plans."""

    @abstractmethod
    def create_snapshot(self, server_id: str, name: str) -> Result[str, str]:
        """Create a server snapshot. Returns provider snapshot ID."""

    @abstractmethod
    def restore_snapshot(self, server_id: str, snapshot_id: str) -> Result[bool, str]:
        """Restore a server from a snapshot."""

    @abstractmethod
    def list_snapshots(self, server_id: str) -> Result[list[dict[str, Any]], str]:
        """List snapshots for a server."""

    @abstractmethod
    def delete_snapshot(self, snapshot_id: str) -> Result[bool, str]:
        """Delete a snapshot by ID."""


# =============================================================================
# Status Normalization — canonical status is "running"
# =============================================================================

_STATUS_MAP: dict[str, str] = {
    "active": "running",  # DigitalOcean, Vultr
    "new": "initializing",  # DigitalOcean
    "archive": "off",  # DigitalOcean
    "pending": "initializing",  # AWS EC2
    "shutting-down": "stopping",  # AWS EC2
    "terminated": "off",  # AWS EC2
    "stopping": "stopping",  # AWS EC2
    "stopped": "off",  # AWS EC2 + Vultr
}


def normalize_server_status(raw_status: str) -> str:
    """
    Normalize provider-specific server status to a canonical vocabulary.

    Canonical statuses returned:
        - "running"       — server is up and serving traffic
        - "stopped"       — server is powered off (maps from "off" internally)
        - "starting"      — server is booting up
        - "stopping"      — server is shutting down
        - "initializing"  — server is being created / first boot
        - "rebuilding"    — server OS is being reinstalled
        - "migrating"     — server is moving between hosts
        - "off"           — server is terminated / archived
        - "unknown"       — status could not be determined

    If *raw_status* is already canonical or unrecognised, it is returned as-is
    (passthrough), so callers should handle unexpected values gracefully.
    """
    return _STATUS_MAP.get(raw_status, raw_status)


# =============================================================================
# Standard Firewall Rules
# =============================================================================

STANDARD_FIREWALL_RULES: list[FirewallRule] = [
    FirewallRule(protocol="tcp", port="22", description="SSH"),
    FirewallRule(protocol="tcp", port="80", description="HTTP"),
    FirewallRule(protocol="tcp", port="443", description="HTTPS"),
    FirewallRule(protocol="tcp", port="10000", description="Webmin"),
]


# =============================================================================
# Provider Registry + Factory
# =============================================================================

_PROVIDER_REGISTRY: dict[str, type[CloudProviderGateway]] = {}
"""
Provider class registry — populated once at startup by each provider module's
``register_cloud_gateway()`` call (typically in ``apps.py`` or at module level).

Because Django's ``AppConfig.ready()`` runs single-threaded during startup,
and the registry is read-only during request handling, no lock is needed.
"""


def register_cloud_gateway(provider_type: str, gateway_cls: type[CloudProviderGateway]) -> None:
    """Register a gateway implementation for a provider type."""
    _PROVIDER_REGISTRY[provider_type] = gateway_cls
    logger.info(f"✅ [CloudGateway] Registered provider: {provider_type}")


def get_cloud_gateway(provider_type: str, token: str, **kwargs: Any) -> CloudProviderGateway:
    """
    Factory function to create a cloud provider gateway.

    Args:
        provider_type: Provider type key (e.g., "hetzner", "digitalocean")
        token: API token for authentication
        **kwargs: Additional provider-specific configuration

    Returns:
        CloudProviderGateway instance

    Raises:
        ValueError: If provider_type is not registered
    """
    gateway_cls = _PROVIDER_REGISTRY.get(provider_type)
    if not gateway_cls:
        available = ", ".join(sorted(_PROVIDER_REGISTRY.keys())) or "(none)"
        raise ValueError(f"Unknown cloud provider: '{provider_type}'. Available: {available}")
    return gateway_cls(token=token, **kwargs)


def get_registered_providers() -> list[str]:
    """Get list of registered provider types."""
    return sorted(_PROVIDER_REGISTRY.keys())
