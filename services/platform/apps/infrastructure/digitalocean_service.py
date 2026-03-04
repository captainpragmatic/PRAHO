"""
DigitalOcean Cloud Service

Wrapper for the pydo Python SDK, implementing CloudProviderGateway.
Provides typed, Pythonic access to DigitalOcean droplet lifecycle operations.

See ADR-0027 for the multi-provider architecture.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any, cast

from pydo import Client

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

# Polling configuration for async DigitalOcean actions
DO_ACTION_POLL_INTERVAL = 5  # seconds between polls
_DEFAULT_DO_ACTION_TIMEOUT = 300  # max seconds to wait for action completion


def _get_do_action_timeout() -> int:
    """Read DO action timeout from SettingsService with DB-cache layer."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return SettingsService.get_integer_setting("infrastructure.do_action_timeout_seconds", _DEFAULT_DO_ACTION_TIMEOUT)


DO_LIST_PER_PAGE = 200  # max items per page for list operations

# Map DigitalOcean region slug prefixes to ISO 3166-1 alpha-2 country codes
DO_REGION_COUNTRY_MAP: dict[str, str] = {
    "nyc": "US",
    "sfo": "US",
    "tor": "CA",
    "lon": "GB",
    "ams": "NL",
    "fra": "DE",
    "sgp": "SG",
    "blr": "IN",
    "syd": "AU",
}


class DigitalOceanService(CloudProviderGateway):
    """
    DigitalOcean SDK wrapper implementing CloudProviderGateway.

    Uses the pydo client library which returns dict-like responses
    from the DigitalOcean API v2.
    """

    def __init__(self, token: str, **_kwargs: Any) -> None:
        self.client = Client(token=token)

    # =========================================================================
    # CloudProviderGateway implementation
    # =========================================================================

    def create_server(self, request: ServerCreateRequest) -> Result[ServerCreateResult, str]:
        """Create a new DigitalOcean droplet."""
        logger.info(f"🚀 [DigitalOcean] Creating droplet: {request.name} ({request.server_type} @ {request.location})")

        try:
            # Idempotency: check for existing droplet by correlation tag
            correlation_tag = request.labels.get("praho-deployment")
            if correlation_tag:
                existing = self._find_droplet_by_tag(f"praho-deployment:{correlation_tag}")
                if existing is not None:
                    droplet_id = str(existing["id"])
                    ipv4 = self._extract_droplet_ipv4(existing)
                    ipv6 = self._extract_droplet_ipv6(existing)
                    logger.info(f"✅ [DigitalOcean] Found existing droplet: {droplet_id} (idempotent)")
                    return Ok(ServerCreateResult(server_id=droplet_id, ipv4_address=ipv4, ipv6_address=ipv6))

            # Build tags from labels
            tags = [f"{k}:{v}" for k, v in request.labels.items()]

            # Resolve SSH key IDs (names must be looked up)
            ssh_key_ids = self._resolve_ssh_key_ids(request.ssh_keys)

            body: dict[str, Any] = {
                "name": request.name,
                "region": request.location,
                "size": request.server_type,
                "image": request.image,
                "ssh_keys": ssh_key_ids,
                "tags": tags,
            }

            response = self.client.droplets.create(body=body)
            droplet = response["droplet"]
            action_id = response.get("links", {}).get("actions", [{}])[0].get("id")

            # Wait for droplet to become active
            if action_id:
                self._wait_for_action(int(action_id))

            # Re-fetch droplet to get network info (not available immediately)
            droplet_id = str(droplet["id"])
            refreshed = self.client.droplets.get(droplet_id=int(droplet_id))
            droplet_data = refreshed["droplet"]

            ipv4 = self._extract_droplet_ipv4(droplet_data)
            ipv6 = self._extract_droplet_ipv6(droplet_data)

            logger.info(f"✅ [DigitalOcean] Droplet created: {request.name} (id={droplet_id}, ip={ipv4})")
            return Ok(ServerCreateResult(server_id=droplet_id, ipv4_address=ipv4, ipv6_address=ipv6))

        except Exception as e:
            logger.error(f"🔥 [DigitalOcean] Droplet creation failed: {e}")
            return Err(f"Droplet creation failed: {e}")

    def delete_server(self, server_id: str) -> Result[bool, str]:
        """Delete a droplet by ID and poll until gone."""
        logger.info(f"🗑️ [DigitalOcean] Deleting droplet: {server_id}")
        try:
            self.client.droplets.destroy(droplet_id=int(server_id))
        except Exception as e:
            error_str = str(e).lower()
            if "not found" in error_str or "404" in error_str:
                logger.info(f"✅ [DigitalOcean] Droplet already gone: {server_id}")
                return Ok(True)
            logger.error(f"🔥 [DigitalOcean] Droplet deletion failed: {e}")
            return Err(f"Droplet deletion failed: {e}")

        # Poll until droplet is gone
        deadline = time.monotonic() + _get_do_action_timeout()
        while time.monotonic() < deadline:
            result = self.get_server(server_id)
            if result.is_ok() and result.unwrap() is None:
                logger.info(f"✅ [DigitalOcean] Droplet deleted: {server_id}")
                return Ok(True)
            time.sleep(DO_ACTION_POLL_INTERVAL)

        logger.warning(f"⚠️ [DigitalOcean] Droplet {server_id} delete requested but still visible after timeout")
        return Ok(True)

    def get_server(self, server_id: str) -> Result[ServerInfo | None, str]:
        """Get droplet info by ID. Returns None if not found."""
        try:
            response = self.client.droplets.get(droplet_id=int(server_id))
            droplet = response["droplet"]
            return Ok(self._droplet_to_server_info(droplet))
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e).lower():
                return Ok(None)
            return Err(f"Failed to get droplet {server_id}: {e}")

    def power_on(self, server_id: str) -> Result[bool, str]:
        """Power on a droplet."""
        return self._droplet_action(server_id, "power_on")

    def power_off(self, server_id: str) -> Result[bool, str]:
        """Power off a droplet."""
        return self._droplet_action(server_id, "power_off")

    def reboot(self, server_id: str) -> Result[bool, str]:
        """Reboot a droplet."""
        return self._droplet_action(server_id, "reboot")

    def resize(self, server_id: str, server_type: str) -> Result[bool, str]:
        """Resize a droplet to a new size slug."""
        try:
            response = self.client.droplet_actions.post(
                droplet_id=int(server_id),
                body={"type": "resize", "size": server_type},
            )
            action_id = response["action"]["id"]
            self._wait_for_action(int(action_id))
            logger.info(f"✅ [DigitalOcean] Droplet resized: {server_id} -> {server_type}")
            return Ok(True)
        except Exception as e:
            return Err(f"Resize failed: {e}")

    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKeyResult, str]:
        """Upload an SSH key. Replaces if name exists with different content."""
        try:
            # Check if key already exists by listing all keys
            existing = self._find_ssh_key_by_name(name)
            if existing:
                if existing.get("public_key", "").strip() != public_key.strip():
                    logger.warning(f"⚠️ [DigitalOcean] SSH key '{name}' exists with different content, replacing")
                    self.client.ssh_keys.delete(ssh_key_identifier=cast(Any, str(existing["id"])))
                else:
                    return Ok(
                        SSHKeyResult(
                            key_id=str(existing["id"]),
                            name=existing["name"],
                            fingerprint=existing.get("fingerprint", ""),
                        )
                    )

            response = self.client.ssh_keys.create(body={"name": name, "public_key": public_key})
            key = response["ssh_key"]
            logger.info(f"✅ [DigitalOcean] SSH key uploaded: {name}")
            return Ok(
                SSHKeyResult(
                    key_id=str(key["id"]),
                    name=key["name"],
                    fingerprint=key.get("fingerprint", ""),
                )
            )
        except Exception as e:
            return Err(f"SSH key upload failed: {e}")

    def delete_ssh_key(self, name: str) -> Result[bool, str]:
        """Delete an SSH key by name."""
        try:
            existing = self._find_ssh_key_by_name(name)
            if not existing:
                return Ok(True)  # Already gone
            self.client.ssh_keys.delete(ssh_key_identifier=cast(Any, str(existing["id"])))
            logger.info(f"✅ [DigitalOcean] SSH key deleted: {name}")
            return Ok(True)
        except Exception as e:
            return Err(f"SSH key deletion failed: {e}")

    def create_firewall(
        self, name: str, rules: list[FirewallRule], labels: dict[str, str] | None = None
    ) -> Result[str, str]:
        """Create a DigitalOcean firewall with rules. Returns firewall ID."""
        try:
            inbound_rules = [
                {
                    "protocol": rule.protocol,
                    "ports": rule.port,
                    "sources": {"addresses": rule.source_ips},
                }
                for rule in rules
            ]

            body: dict[str, Any] = {
                "name": name,
                "inbound_rules": inbound_rules,
                "outbound_rules": [
                    {"protocol": "tcp", "ports": "all", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                    {"protocol": "udp", "ports": "all", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                    {"protocol": "icmp", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                ],
            }
            if labels:
                body["tags"] = [f"{k}:{v}" for k, v in labels.items()]

            response = self.client.firewalls.create(body=body)
            firewall = response["firewall"]
            fw_id = str(firewall["id"])
            logger.info(f"✅ [DigitalOcean] Firewall created: {name} (id={fw_id})")
            return Ok(fw_id)
        except Exception as e:
            return Err(f"Firewall creation failed: {e}")

    def delete_firewall(self, firewall_id: str) -> Result[bool, str]:
        """Delete a DigitalOcean firewall by ID."""
        try:
            self.client.firewalls.delete(firewall_id=firewall_id)
            logger.info(f"✅ [DigitalOcean] Firewall deleted: {firewall_id}")
            return Ok(True)
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e).lower():
                return Ok(True)
            return Err(f"Firewall deletion failed: {e}")

    def get_locations(self) -> Result[Sequence[LocationInfo], str]:
        """Get all available DigitalOcean regions."""
        try:
            all_regions: list[LocationInfo] = []
            page = 1
            while True:
                response = self.client.regions.list(per_page=DO_LIST_PER_PAGE, page=page)
                regions = response.get("regions", [])
                if not regions:
                    break
                for region in regions:
                    if region.get("available", False):
                        slug = region["slug"]
                        # Extract prefix (letters before digits) for country lookup
                        prefix = "".join(c for c in slug if c.isalpha())
                        country = DO_REGION_COUNTRY_MAP.get(prefix, prefix.upper()[:2])
                        all_regions.append(
                            LocationInfo(
                                name=slug,
                                description=region.get("name", ""),
                                country=country,
                                city=region.get("name", ""),
                            )
                        )
                if len(regions) < DO_LIST_PER_PAGE:
                    break
                page += 1
            return Ok(all_regions)
        except Exception as e:
            return Err(f"Failed to get regions: {e}")

    def get_server_types(self) -> Result[Sequence[ServerTypeInfo], str]:
        """Get all available DigitalOcean droplet sizes."""
        try:
            all_sizes: list[ServerTypeInfo] = []
            page = 1
            while True:
                response = self.client.sizes.list(per_page=DO_LIST_PER_PAGE, page=page)
                sizes = response.get("sizes", [])
                if not sizes:
                    break
                all_sizes.extend(
                    ServerTypeInfo(
                        name=size["slug"],
                        description=f"{size.get('vcpus', 0)} vCPU / {size.get('memory', 0)}MB RAM / {size.get('disk', 0)}GB",
                        vcpus=size.get("vcpus", 0),
                        memory_gb=size.get("memory", 0) / 1024,
                        disk_gb=size.get("disk", 0),
                    )
                    for size in sizes
                    if size.get("available", False)
                )
                if len(sizes) < DO_LIST_PER_PAGE:
                    break
                page += 1
            return Ok(all_sizes)
        except Exception as e:
            return Err(f"Failed to get sizes: {e}")

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _droplet_action(self, server_id: str, action_type: str) -> Result[bool, str]:
        """Execute a droplet action and wait for completion."""
        try:
            response = self.client.droplet_actions.post(
                droplet_id=int(server_id),
                body={"type": action_type},
            )
            action_id = response["action"]["id"]
            self._wait_for_action(int(action_id))
            logger.info(f"✅ [DigitalOcean] Droplet {action_type}: {server_id}")
            return Ok(True)
        except Exception as e:
            return Err(f"{action_type} failed: {e}")

    def _wait_for_action(self, action_id: int) -> None:
        """Poll an action until it completes or times out."""
        deadline = time.monotonic() + _get_do_action_timeout()
        while time.monotonic() < deadline:
            response = self.client.actions.get(action_id=action_id)
            status = response["action"]["status"]
            if status == "completed":
                return
            if status == "errored":
                raise RuntimeError(f"Action {action_id} errored")
            time.sleep(DO_ACTION_POLL_INTERVAL)
        raise TimeoutError(f"Action {action_id} timed out after {_get_do_action_timeout()}s")

    def _find_droplet_by_tag(self, tag: str) -> dict[str, Any] | None:
        """Find a droplet by tag name. Returns first match or None."""
        response = self.client.droplets.list(tag_name=tag, per_page=1)
        droplets = response.get("droplets", [])
        if droplets:
            return cast(dict[str, Any], droplets[0])
        return None

    def _find_ssh_key_by_name(self, name: str) -> dict[str, Any] | None:
        """Find an SSH key by name. Returns first match or None."""
        page = 1
        while True:
            response = self.client.ssh_keys.list(per_page=DO_LIST_PER_PAGE, page=page)
            keys = response.get("ssh_keys", [])
            if not keys:
                break
            for key in keys:
                if key.get("name") == name:
                    return cast(dict[str, Any], key)
            if len(keys) < DO_LIST_PER_PAGE:
                break
            page += 1
        return None

    def _resolve_ssh_key_ids(self, ssh_key_names: list[str]) -> list[int]:
        """Resolve SSH key names to IDs for droplet creation."""
        if not ssh_key_names:
            return []
        ids: list[int] = []
        for name in ssh_key_names:
            key = self._find_ssh_key_by_name(name)
            if key:
                ids.append(int(key["id"]))
            else:
                logger.warning(f"⚠️ [DigitalOcean] SSH key '{name}' not found on DigitalOcean")
        return ids

    @staticmethod
    def _extract_droplet_ipv4(droplet: dict[str, Any]) -> str:
        """Extract the public IPv4 address from a droplet dict."""
        for network in droplet.get("networks", {}).get("v4", []):
            if network.get("type") == "public":
                return str(network.get("ip_address", ""))
        return ""

    @staticmethod
    def _extract_droplet_ipv6(droplet: dict[str, Any]) -> str:
        """Extract the public IPv6 address from a droplet dict."""
        for network in droplet.get("networks", {}).get("v6", []):
            if network.get("type") == "public":
                return str(network.get("ip_address", ""))
        return ""

    @staticmethod
    def _droplet_to_server_info(droplet: dict[str, Any]) -> ServerInfo:
        """Convert a DigitalOcean droplet dict to gateway ServerInfo."""
        # Convert tags to labels dict
        labels: dict[str, str] = {}
        for tag in droplet.get("tags", []):
            if ":" in tag:
                k, v = tag.split(":", 1)
                labels[k] = v

        return ServerInfo(
            server_id=str(droplet["id"]),
            name=droplet.get("name", ""),
            status=normalize_server_status(droplet.get("status", "")),
            ipv4_address=DigitalOceanService._extract_droplet_ipv4(droplet),
            ipv6_address=DigitalOceanService._extract_droplet_ipv6(droplet),
            server_type=droplet.get("size_slug", ""),
            location=droplet.get("region", {}).get("slug", "") if isinstance(droplet.get("region"), dict) else "",
            labels=labels,
        )

    # =========================================================================
    # Snapshot operations (stubs — not yet implemented for DigitalOcean)
    # =========================================================================

    def create_snapshot(self, server_id: str, name: str) -> Result[str, str]:
        """Create a server snapshot. Not yet implemented for DigitalOcean."""
        return Err("Snapshot creation not yet implemented for DigitalOcean")

    def restore_snapshot(self, server_id: str, snapshot_id: str) -> Result[bool, str]:
        """Restore a server from a snapshot. Not yet implemented for DigitalOcean."""
        return Err("Snapshot restore not yet implemented for DigitalOcean")

    def list_snapshots(self, server_id: str) -> Result[list[dict[str, Any]], str]:
        """List snapshots for a server. Not yet implemented for DigitalOcean."""
        return Err("List snapshots not yet implemented for DigitalOcean")

    def delete_snapshot(self, snapshot_id: str) -> Result[bool, str]:
        """Delete a snapshot by ID. Not yet implemented for DigitalOcean."""
        return Err("Snapshot deletion not yet implemented for DigitalOcean")


# Register DigitalOcean as a cloud gateway provider
register_cloud_gateway("digitalocean", DigitalOceanService)


def get_digitalocean_service(token: str) -> DigitalOceanService:
    """Create a DigitalOceanService instance with the given API token."""
    return DigitalOceanService(token=token)
