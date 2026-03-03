"""
Hetzner Cloud Service

Wrapper for the hcloud Python SDK, replacing Terraform for Hetzner server provisioning.
Provides typed, Pythonic access to server lifecycle operations.

See ADR-0027 for migration rationale.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from hcloud import Client
from hcloud.images.domain import Image
from hcloud.locations.domain import Location
from hcloud.server_types.domain import ServerType
from hcloud.servers.domain import Server
from hcloud.ssh_keys.domain import SSHKey

from apps.common.types import Err, Ok, Result

logger = logging.getLogger(__name__)


@dataclass
class HcloudResult:
    """Result of an hcloud operation."""

    success: bool
    server_id: str = ""
    ipv4_address: str = ""
    ipv6_address: str = ""
    root_password: str = ""
    error: str = ""


@dataclass
class HcloudServerInfo:
    """Snapshot of server state from the API."""

    server_id: int
    name: str
    status: str
    ipv4_address: str
    ipv6_address: str
    server_type: str
    location: str
    labels: dict[str, str]


class HcloudService:
    """
    Hetzner Cloud SDK wrapper for server provisioning.

    Replaces TerraformService for Hetzner-specific operations. Our database
    (NodeDeployment model) IS the state — no Terraform state files needed.
    """

    def __init__(self, token: str) -> None:
        self.client = Client(token=token)

    def create_server(  # noqa: PLR0913
        self,
        name: str,
        server_type: str,
        location: str,
        ssh_keys: list[str],
        image: str = "ubuntu-22.04",
        labels: dict[str, str] | None = None,
    ) -> Result[HcloudResult, str]:
        """
        Create a new Hetzner Cloud server.

        Args:
            name: Server hostname
            server_type: Hetzner server type (e.g., "cpx21", "cpx41")
            location: Hetzner location (e.g., "fsn1", "nbg1")
            ssh_keys: List of SSH key names registered in Hetzner
            image: OS image name (default: ubuntu-22.04)
            labels: Optional labels for the server

        Returns:
            Result with HcloudResult or error string
        """
        logger.info(f"🚀 [Hcloud] Creating server: {name} ({server_type} @ {location})")

        try:
            response = self.client.servers.create(
                name=name,
                server_type=ServerType(name=server_type),
                image=Image(name=image),
                location=Location(name=location),
                ssh_keys=[SSHKey(name=k) for k in ssh_keys],
                labels=labels or {},
            )

            server = response.server
            action = response.action

            # Wait for server to be running
            action.wait_until_finished()

            ipv4 = ""
            ipv6 = ""
            if server.public_net:
                if server.public_net.ipv4:
                    ipv4 = server.public_net.ipv4.ip
                if server.public_net.ipv6:
                    ipv6 = server.public_net.ipv6.ip

            result = HcloudResult(
                success=True,
                server_id=str(server.id),
                ipv4_address=ipv4,
                ipv6_address=ipv6,
                root_password=response.root_password or "",
            )

            logger.info(f"✅ [Hcloud] Server created: {name} (id={server.id}, ip={ipv4})")
            return Ok(result)

        except Exception as e:
            logger.error(f"🔥 [Hcloud] Server creation failed: {e}")
            return Err(f"Server creation failed: {e}")

    def delete_server(self, server_id: int) -> Result[HcloudResult, str]:
        """Delete a server by ID."""
        logger.info(f"🗑️ [Hcloud] Deleting server: {server_id}")

        try:
            server = self.client.servers.get_by_id(server_id)
            action = self.client.servers.delete(server)
            action.wait_until_finished()

            logger.info(f"✅ [Hcloud] Server deleted: {server_id}")
            return Ok(HcloudResult(success=True, server_id=str(server_id)))

        except Exception as e:
            logger.error(f"🔥 [Hcloud] Server deletion failed: {e}")
            return Err(f"Server deletion failed: {e}")

    def get_server(self, server_id: int) -> Result[HcloudServerInfo, str]:
        """Get server info by ID."""
        try:
            server = self.client.servers.get_by_id(server_id)
            return Ok(self._server_to_info(server))

        except Exception as e:
            return Err(f"Failed to get server {server_id}: {e}")

    def power_on(self, server_id: int) -> Result[bool, str]:
        """Power on a server."""
        try:
            server = self.client.servers.get_by_id(server_id)
            action = self.client.servers.power_on(server)
            action.wait_until_finished()
            logger.info(f"✅ [Hcloud] Server powered on: {server_id}")
            return Ok(True)
        except Exception as e:
            return Err(f"Power on failed: {e}")

    def power_off(self, server_id: int) -> Result[bool, str]:
        """Power off a server."""
        try:
            server = self.client.servers.get_by_id(server_id)
            action = self.client.servers.power_off(server)
            action.wait_until_finished()
            logger.info(f"✅ [Hcloud] Server powered off: {server_id}")
            return Ok(True)
        except Exception as e:
            return Err(f"Power off failed: {e}")

    def reboot(self, server_id: int) -> Result[bool, str]:
        """Reboot a server."""
        try:
            server = self.client.servers.get_by_id(server_id)
            action = self.client.servers.reboot(server)
            action.wait_until_finished()
            logger.info(f"✅ [Hcloud] Server rebooted: {server_id}")
            return Ok(True)
        except Exception as e:
            return Err(f"Reboot failed: {e}")

    def resize(self, server_id: int, server_type: str, upgrade_disk: bool = True) -> Result[bool, str]:
        """Resize a server to a new type."""
        try:
            server = self.client.servers.get_by_id(server_id)
            action = self.client.servers.change_type(
                server,
                server_type=ServerType(name=server_type),
                upgrade_disk=upgrade_disk,
            )
            action.wait_until_finished()
            logger.info(f"✅ [Hcloud] Server resized: {server_id} -> {server_type}")
            return Ok(True)
        except Exception as e:
            return Err(f"Resize failed: {e}")

    def get_locations(self) -> Result[list[Location], str]:
        """Get all available locations."""
        try:
            locations = self.client.locations.get_all()
            return Ok(locations)
        except Exception as e:
            return Err(f"Failed to get locations: {e}")

    def get_server_types(self) -> Result[list[ServerType], str]:
        """Get all available server types."""
        try:
            server_types = self.client.server_types.get_all()
            return Ok(server_types)
        except Exception as e:
            return Err(f"Failed to get server types: {e}")

    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKey, str]:
        """Upload an SSH key to Hetzner Cloud."""
        try:
            # Check if key already exists
            existing = self.client.ssh_keys.get_by_name(name)
            if existing:
                return Ok(existing)

            ssh_key = self.client.ssh_keys.create(name=name, public_key=public_key)
            logger.info(f"✅ [Hcloud] SSH key uploaded: {name}")
            return Ok(ssh_key)
        except Exception as e:
            return Err(f"SSH key upload failed: {e}")

    def _server_to_info(self, server: Server | Any) -> HcloudServerInfo:
        """Convert hcloud Server domain object to our info dataclass."""
        ipv4 = ""
        ipv6 = ""
        if server.public_net:
            if server.public_net.ipv4:
                ipv4 = server.public_net.ipv4.ip
            if server.public_net.ipv6:
                ipv6 = server.public_net.ipv6.ip

        return HcloudServerInfo(
            server_id=server.id,
            name=server.name or "",
            status=server.status or "",
            ipv4_address=ipv4,
            ipv6_address=ipv6,
            server_type=server.server_type.name if server.server_type else "",
            location=server.location.name if server.location else "",
            labels=server.labels or {},
        )


# Factory function — no singleton; token comes from CredentialVault per-request
def get_hcloud_service(token: str) -> HcloudService:
    """Create an HcloudService instance with the given API token."""
    return HcloudService(token=token)
