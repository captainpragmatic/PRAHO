"""
Hetzner Cloud Service

Wrapper for the hcloud Python SDK, implementing CloudProviderGateway.
Provides typed, Pythonic access to server lifecycle operations.

See ADR-0027 for migration rationale.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from hcloud import Client
from hcloud.firewalls.domain import Firewall
from hcloud.firewalls.domain import FirewallRule as HcloudFirewallRule
from hcloud.images.domain import Image
from hcloud.locations.domain import Location
from hcloud.server_types.domain import ServerType
from hcloud.servers.domain import Server
from hcloud.ssh_keys.domain import SSHKey

from apps.common.types import Err, Ok, Result
from apps.infrastructure.cloud_gateway import (
    CloudProviderGateway,
    FirewallRule,
    LocationInfo,
    ServerCreateRequest,
    ServerCreateResult,
    ServerInfo,
    ServerTypeInfo,
    SSHKeyResult,
    normalize_server_status,
    register_cloud_gateway,
)

logger = logging.getLogger(__name__)

# Max retries for hcloud action polling (~5 min timeout at 1s intervals)
HCLOUD_ACTION_MAX_RETRIES = 300


class HcloudService(CloudProviderGateway):
    """
    Hetzner Cloud SDK wrapper implementing CloudProviderGateway.

    Our database (NodeDeployment model) IS the state — no external state files needed.
    """

    def __init__(self, token: str, **_kwargs: Any) -> None:
        self.client = Client(token=token)

    # =========================================================================
    # CloudProviderGateway implementation (unified interface)
    # =========================================================================

    def create_server(self, request: ServerCreateRequest) -> Result[ServerCreateResult, str]:
        """Create a new Hetzner Cloud server."""
        req = request

        logger.info(f"🚀 [Hcloud] Creating server: {req.name} ({req.server_type} @ {req.location})")

        try:
            correlation_id = req.labels.get("praho-deployment", "")
            if correlation_id:
                existing = self.client.servers.get_all(label_selector=f"praho-deployment={correlation_id}")
                if existing:
                    server = existing[0]
                    logger.info(f"✅ [Hcloud] Found existing server for deployment {correlation_id}: {server.id}")
                    ipv4, ipv6 = self._extract_ips(server)
                    return Ok(
                        ServerCreateResult(
                            server_id=str(server.id),
                            ipv4_address=ipv4,
                            ipv6_address=ipv6,
                            root_password="",
                        )
                    )

            # Build firewall list if specified
            firewalls: list[Firewall] = [Firewall(id=int(fw_id)) for fw_id in req.firewall_ids]

            create_kwargs: dict[str, Any] = {
                "name": req.name,
                "server_type": ServerType(name=req.server_type),
                "image": Image(name=req.image),
                "location": Location(name=req.location),
                "ssh_keys": [SSHKey(name=k) for k in req.ssh_keys],
                "labels": req.labels,
            }
            if firewalls:
                create_kwargs["firewalls"] = firewalls

            response = self.client.servers.create(**create_kwargs)

            server = response.server
            action = response.action

            # Wait for server to be running
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)

            ipv4 = ""
            ipv6 = ""
            if server.public_net:
                if server.public_net.ipv4:
                    ipv4 = server.public_net.ipv4.ip
                if server.public_net.ipv6:
                    ipv6 = server.public_net.ipv6.ip

            logger.info(f"✅ [Hcloud] Server created: {req.name} (id={server.id}, ip={ipv4})")

            # Return gateway type if called via gateway interface, else backward-compat type
            return Ok(
                ServerCreateResult(
                    server_id=str(server.id),
                    ipv4_address=ipv4,
                    ipv6_address=ipv6,
                    root_password=response.root_password or "",
                )
            )

        except Exception as e:
            logger.error(f"🔥 [Hcloud] Server creation failed: {e}")
            return Err(f"Server creation failed: {e}")

    def delete_server(self, server_id: str) -> Result[bool, str]:
        """Delete a server by ID."""
        try:
            sid = int(server_id)
            logger.info(f"🗑️ [Hcloud] Deleting server: {sid}")
            server = self.client.servers.get_by_id(sid)
            if not server:
                return Ok(True)
            action = self.client.servers.delete(server)
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)

            logger.info(f"✅ [Hcloud] Server deleted: {sid}")
            return Ok(True)

        except Exception as e:
            logger.error(f"🔥 [Hcloud] Server deletion failed: {e}")
            return Err(f"Server deletion failed: {e}")

    def get_server(self, server_id: str) -> Result[ServerInfo | None, str]:
        """Get server info by ID. Returns None if not found."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            if not server:
                return Ok(None)

            return Ok(self._server_to_gateway_info(server))

        except Exception as e:
            # If server not found, return None instead of error
            if "not found" in str(e).lower():
                return Ok(None)
            return Err(f"Failed to get server {server_id}: {e}")

    def power_on(self, server_id: str) -> Result[bool, str]:
        """Power on a server."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            action = self.client.servers.power_on(server)
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            logger.info(f"✅ [Hcloud] Server powered on: {sid}")
            return Ok(True)
        except Exception as e:
            return Err(f"Power on failed: {e}")

    def power_off(self, server_id: str) -> Result[bool, str]:
        """Power off a server."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            action = self.client.servers.power_off(server)
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            logger.info(f"✅ [Hcloud] Server powered off: {sid}")
            return Ok(True)
        except Exception as e:
            return Err(f"Power off failed: {e}")

    def reboot(self, server_id: str) -> Result[bool, str]:
        """Reboot a server."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            action = self.client.servers.reboot(server)
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            logger.info(f"✅ [Hcloud] Server rebooted: {sid}")
            return Ok(True)
        except Exception as e:
            return Err(f"Reboot failed: {e}")

    def resize(self, server_id: str, server_type: str, upgrade_disk: bool = True) -> Result[bool, str]:
        """Resize a server to a new type."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            action = self.client.servers.change_type(
                server,
                server_type=ServerType(name=server_type),
                upgrade_disk=upgrade_disk,
            )
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            logger.info(f"✅ [Hcloud] Server resized: {sid} -> {server_type}")
            return Ok(True)
        except Exception as e:
            return Err(f"Resize failed: {e}")

    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKeyResult, str]:
        """Upload an SSH key to Hetzner Cloud. Replaces if content differs."""
        try:
            # Check if key already exists
            existing = self.client.ssh_keys.get_by_name(name)
            if existing:
                # Verify the key content matches; if different, replace it
                if existing.public_key and existing.public_key.strip() != public_key.strip():
                    logger.warning(f"⚠️ [Hcloud] SSH key '{name}' exists with different content, replacing")
                    self.client.ssh_keys.delete(existing)
                else:
                    return Ok(
                        SSHKeyResult(
                            key_id=str(existing.id),
                            name=existing.name or name,
                            fingerprint=existing.fingerprint or "",
                        )
                    )

            ssh_key = self.client.ssh_keys.create(name=name, public_key=public_key)
            logger.info(f"✅ [Hcloud] SSH key uploaded: {name}")
            return Ok(
                SSHKeyResult(
                    key_id=str(ssh_key.id),
                    name=ssh_key.name or name,
                    fingerprint=ssh_key.fingerprint or "",
                )
            )
        except Exception as e:
            return Err(f"SSH key upload failed: {e}")

    def delete_ssh_key(self, name: str) -> Result[bool, str]:
        """Delete an SSH key from Hetzner Cloud by name."""
        try:
            existing = self.client.ssh_keys.get_by_name(name)
            if not existing:
                return Ok(True)  # Already gone
            self.client.ssh_keys.delete(existing)
            logger.info(f"✅ [Hcloud] SSH key deleted: {name}")
            return Ok(True)
        except Exception as e:
            return Err(f"SSH key deletion failed: {e}")

    def create_firewall(
        self, name: str, rules: list[FirewallRule], labels: dict[str, str] | None = None
    ) -> Result[str, str]:
        """Create a Hetzner Cloud firewall with rules. Returns firewall ID."""
        try:
            hcloud_rules: list[HcloudFirewallRule] = [
                HcloudFirewallRule(
                    direction=rule.direction,
                    protocol=rule.protocol,
                    port=rule.port,
                    source_ips=rule.source_ips,
                    description=rule.description,
                )
                for rule in rules
            ]

            response = self.client.firewalls.create(
                name=name,
                rules=hcloud_rules,
                labels=labels,
            )
            firewall = response.firewall
            logger.info(f"✅ [Hcloud] Firewall created: {name} (id={firewall.id})")
            return Ok(str(firewall.id))
        except Exception as e:
            return Err(f"Firewall creation failed: {e}")

    def delete_firewall(self, firewall_id: str) -> Result[bool, str]:
        """Delete a Hetzner Cloud firewall by ID."""
        try:
            firewall = self.client.firewalls.get_by_id(int(firewall_id))
            if not firewall:
                return Ok(True)  # Already gone
            self.client.firewalls.delete(firewall)
            logger.info(f"✅ [Hcloud] Firewall deleted: {firewall_id}")
            return Ok(True)
        except Exception as e:
            return Err(f"Firewall deletion failed: {e}")

    def get_locations(self) -> Result[Sequence[LocationInfo], str]:
        """Get all available locations."""
        try:
            locations = self.client.locations.get_all()
            return Ok(
                [
                    LocationInfo(
                        name=str(loc.name),
                        description=str(loc.description or ""),
                        country=str(loc.country or ""),
                        city=str(loc.city or ""),
                    )
                    for loc in locations
                ]
            )
        except Exception as e:
            return Err(f"Failed to get locations: {e}")

    def get_server_types(self) -> Result[Sequence[ServerTypeInfo], str]:
        """Get all available server types."""
        try:
            server_types = self.client.server_types.get_all()
            results: list[ServerTypeInfo] = []
            for st in server_types:
                price_monthly = self._extract_monthly_price(st.prices)
                results.append(
                    ServerTypeInfo(
                        name=str(st.name),
                        description=str(st.description or ""),
                        vcpus=int(st.cores or 0),
                        memory_gb=float(st.memory or 0),
                        disk_gb=int(st.disk or 0),
                        price_monthly=price_monthly,
                        available=not bool(st.deprecated),
                    )
                )
            return Ok(results)
        except Exception as e:
            return Err(f"Failed to get server types: {e}")

    @staticmethod
    def _extract_monthly_price(prices: Any) -> float:
        """Extract EUR monthly price from hcloud prices list. Prefers fsn1 location."""
        if not prices:
            return 0.0
        chosen = None
        for entry in prices:
            if not isinstance(entry, dict):
                continue
            if entry.get("location") == "fsn1":
                chosen = entry
                break
            if chosen is None:
                chosen = entry
        if chosen is None:
            return 0.0
        price_monthly = chosen.get("price_monthly")
        if isinstance(price_monthly, dict):
            return float(price_monthly.get("gross", 0.0))
        return 0.0

    # =========================================================================
    # Snapshot operations (CloudProviderGateway ABC)
    # =========================================================================

    def create_snapshot(self, server_id: str, name: str) -> Result[str, str]:
        """Create a server snapshot. Returns provider snapshot ID."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            response = self.client.servers.create_image(server, description=name, type="snapshot")
            action = response.action
            action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            image = response.image
            logger.info(f"✅ [Hcloud] Snapshot created: {name} (id={image.id}) for server {sid}")
            return Ok(str(image.id))
        except Exception as e:
            logger.error(f"🔥 [Hcloud] Snapshot creation failed for server {server_id}: {e}")
            return Err(f"Snapshot creation failed: {e}")

    def restore_snapshot(self, server_id: str, snapshot_id: str) -> Result[bool, str]:
        """Restore a server from a snapshot."""
        try:
            sid = int(server_id)
            server = self.client.servers.get_by_id(sid)
            rebuild_response = self.client.servers.rebuild(server, image=Image(id=int(snapshot_id)))
            rebuild_response.action.wait_until_finished(max_retries=HCLOUD_ACTION_MAX_RETRIES)
            logger.info(f"✅ [Hcloud] Server {sid} restored from snapshot {snapshot_id}")
            return Ok(True)
        except Exception as e:
            logger.error(f"🔥 [Hcloud] Snapshot restore failed for server {server_id}: {e}")
            return Err(f"Snapshot restore failed: {e}")

    def list_snapshots(self, server_id: str) -> Result[list[dict[str, Any]], str]:
        """List snapshots for a server (filtered by label)."""
        try:
            images = self.client.images.get_all(type=["snapshot"], sort=["created:desc"])
            results: list[dict[str, Any]] = []
            for img in images:
                # Filter by server label if available
                labels = img.labels or {}
                label_match = labels.get("server_id") == server_id
                created_from = img.created_from
                source_match = (str(created_from.id) == server_id) if created_from is not None else False
                if label_match or source_match:
                    results.append(
                        {
                            "id": str(img.id),
                            "description": str(img.description or ""),
                            "created": str(img.created) if img.created else "",
                            "image_size": img.image_size,
                        }
                    )
            return Ok(results)
        except Exception as e:
            logger.error(f"🔥 [Hcloud] List snapshots failed for server {server_id}: {e}")
            return Err(f"List snapshots failed: {e}")

    def delete_snapshot(self, snapshot_id: str) -> Result[bool, str]:
        """Delete a snapshot by ID."""
        try:
            image = self.client.images.get_by_id(int(snapshot_id))
            if not image:
                return Ok(True)  # Already gone
            self.client.images.delete(image)
            logger.info(f"✅ [Hcloud] Snapshot deleted: {snapshot_id}")
            return Ok(True)
        except Exception as e:
            logger.error(f"🔥 [Hcloud] Snapshot deletion failed: {e}")
            return Err(f"Snapshot deletion failed: {e}")

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _server_to_gateway_info(self, server: Server | Any) -> ServerInfo:
        """Convert hcloud Server domain object to gateway ServerInfo."""
        ipv4, ipv6 = self._extract_ips(server)
        return ServerInfo(
            server_id=str(server.id or ""),
            name=str(server.name or ""),
            status=normalize_server_status(str(server.status or "")),
            ipv4_address=ipv4,
            ipv6_address=ipv6,
            server_type=str(server.server_type.name) if server.server_type else "",
            location=str(server.location.name) if server.location else "",
            labels=server.labels or {},
        )

    @staticmethod
    def _extract_ips(server: Server | Any) -> tuple[str, str]:
        """Extract IPv4 and IPv6 addresses from server."""
        ipv4 = ""
        ipv6 = ""
        if server.public_net:
            if server.public_net.ipv4:
                ipv4 = server.public_net.ipv4.ip
            if server.public_net.ipv6:
                ipv6 = server.public_net.ipv6.ip
        return ipv4, ipv6


# Register Hetzner as a cloud gateway provider
register_cloud_gateway("hetzner", HcloudService)


# Factory function — no singleton; token comes from CredentialVault per-request
def get_hcloud_service(token: str) -> HcloudService:
    """Create an HcloudService instance with the given API token."""
    return HcloudService(token=token)
