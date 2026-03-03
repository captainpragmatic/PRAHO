"""
Vultr Cloud Service

REST API v2 wrapper implementing CloudProviderGateway.
Uses requests directly against https://api.vultr.com/v2/.

See ADR-0027 for multi-provider architecture.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Sequence
from typing import Any

import requests

from apps.common.types import Err, Ok, Result

HTTP_NOT_FOUND = 404
IPV4_VERSION = 4
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

VULTR_API_BASE = "https://api.vultr.com/v2"
VULTR_POLL_INTERVAL = 5
VULTR_POLL_TIMEOUT = 300


class VultrService(CloudProviderGateway):
    """
    Vultr Cloud API v2 wrapper implementing CloudProviderGateway.

    Uses requests with Bearer token auth against the Vultr REST API.
    """

    def __init__(self, token: str, **_kwargs: Any) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Make an authenticated request to the Vultr API."""
        url = f"{VULTR_API_BASE}{path}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _wait_for_active(self, instance_id: str) -> Result[dict[str, Any], str]:
        """Poll instance until status is 'active' or timeout."""
        deadline = time.monotonic() + VULTR_POLL_TIMEOUT
        while time.monotonic() < deadline:
            resp = self._request("GET", f"/instances/{instance_id}")
            data: dict[str, Any] = resp.json().get("instance", {})
            if data.get("status") == "active" and data.get("power_status") == "running":
                return Ok(data)
            time.sleep(VULTR_POLL_INTERVAL)
        return Err(f"Instance {instance_id} did not become active within {VULTR_POLL_TIMEOUT}s")

    def _wait_for_status(self, instance_id: str, target_statuses: list[str]) -> Result[bool, str]:
        """Poll instance until normalized status is in target_statuses or timeout."""
        deadline = time.monotonic() + VULTR_POLL_TIMEOUT
        while time.monotonic() < deadline:
            result = self.get_server(instance_id)
            if result.is_err():
                return Err(result.unwrap_err())
            server = result.unwrap()
            if server is not None and server.status in target_statuses:
                return Ok(True)
            time.sleep(VULTR_POLL_INTERVAL)
        return Err(f"Instance {instance_id} did not reach {target_statuses} within {VULTR_POLL_TIMEOUT}s")

    def _find_instance_by_label(self, label_value: str) -> dict[str, Any] | None:
        """Find an instance by its label (used for idempotency)."""
        resp = self._request("GET", "/instances", params={"label": label_value})
        instances: list[dict[str, Any]] = resp.json().get("instances", [])
        for inst in instances:
            if inst.get("label") == label_value:
                return inst
        return None

    # =========================================================================
    # CloudProviderGateway implementation
    # =========================================================================

    def create_server(self, request: ServerCreateRequest) -> Result[ServerCreateResult, str]:
        """Create a new Vultr instance."""
        if not request.image:
            return Err("Image required: Vultr needs a valid image or OS identifier")

        correlation_id = request.labels.get("praho-deployment", "")
        logger.info(f"🚀 [Vultr] Creating instance: {request.name} ({request.server_type} @ {request.location})")

        try:
            # Idempotency: check if instance with this correlation_id already exists
            if correlation_id:
                existing = self._find_instance_by_label(correlation_id)
                if existing:
                    logger.info(f"✅ [Vultr] Found existing instance for correlation_id={correlation_id}")
                    return Ok(ServerCreateResult(
                        server_id=existing["id"],
                        ipv4_address=existing.get("main_ip", ""),
                        ipv6_address=existing.get("v6_main_ip", ""),
                    ))

            payload: dict[str, Any] = {
                "region": request.location,
                "plan": request.server_type,
                "os_id": 0,  # Will use image_id instead
                "label": correlation_id or request.name,
                "hostname": request.name,
                "tags": [f"{k}={v}" for k, v in request.labels.items()],
            }

            # Vultr uses os_id or image_id; for snapshots use image_id
            # For standard OS images, use the image slug
            if request.image:
                payload["image_id"] = request.image
                payload.pop("os_id", None)

            if request.ssh_keys:
                payload["sshkey_id"] = request.ssh_keys

            if request.firewall_ids:
                payload["firewall_group_id"] = request.firewall_ids[0]

            resp = self._request("POST", "/instances", json=payload)
            instance: dict[str, Any] = resp.json().get("instance", {})
            instance_id: str = instance.get("id", "")

            # Wait for instance to become active
            poll_result = self._wait_for_active(instance_id)
            if poll_result.is_err():
                return Err(poll_result.unwrap_err())

            active_instance = poll_result.unwrap()
            ipv4 = str(active_instance.get("main_ip", ""))
            ipv6 = str(active_instance.get("v6_main_ip", ""))

            logger.info(f"✅ [Vultr] Instance created: {request.name} (id={instance_id}, ip={ipv4})")
            return Ok(ServerCreateResult(
                server_id=instance_id,
                ipv4_address=ipv4,
                ipv6_address=ipv6,
            ))

        except Exception as e:
            logger.error(f"🔥 [Vultr] Instance creation failed: {e}")
            return Err(f"Instance creation failed: {e}")

    def delete_server(self, server_id: str) -> Result[bool, str]:
        """Delete an instance by ID. Returns Ok(True) if already gone (404)."""
        logger.info(f"🗑️ [Vultr] Deleting instance: {server_id}")
        try:
            self._request("DELETE", f"/instances/{server_id}")
            logger.info(f"✅ [Vultr] Instance deleted: {server_id}")
            return Ok(True)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTP_NOT_FOUND:
                logger.info(f"✅ [Vultr] Instance already gone: {server_id}")
                return Ok(True)
            logger.error(f"🔥 [Vultr] Instance deletion failed: {e}")
            return Err(f"Instance deletion failed: {e}")
        except Exception as e:
            logger.error(f"🔥 [Vultr] Instance deletion failed: {e}")
            return Err(f"Instance deletion failed: {e}")

    def get_server(self, server_id: str) -> Result[ServerInfo | None, str]:
        """Get instance info by ID."""
        try:
            resp = self._request("GET", f"/instances/{server_id}")
            data: dict[str, Any] = resp.json().get("instance", {})
            if not data:
                return Ok(None)

            tags = data.get("tags", [])
            labels: dict[str, str] = {}
            for tag in tags:
                if "=" in tag:
                    k, v = tag.split("=", 1)
                    labels[k] = v

            return Ok(ServerInfo(
                server_id=data.get("id", ""),
                name=data.get("label", ""),
                status=normalize_server_status(data.get("status", "")),
                ipv4_address=data.get("main_ip", ""),
                ipv6_address=data.get("v6_main_ip", ""),
                server_type=data.get("plan", ""),
                location=data.get("region", ""),
                labels=labels,
            ))
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTP_NOT_FOUND:
                return Ok(None)
            return Err(f"Failed to get instance {server_id}: {e}")
        except Exception as e:
            return Err(f"Failed to get instance {server_id}: {e}")

    def power_on(self, server_id: str) -> Result[bool, str]:
        """Power on an instance and wait until running."""
        try:
            self._request("POST", f"/instances/{server_id}/start")
            logger.info(f"✅ [Vultr] Instance power on requested: {server_id}")
            return self._wait_for_status(server_id, ["running"])
        except Exception as e:
            return Err(f"Power on failed: {e}")

    def power_off(self, server_id: str) -> Result[bool, str]:
        """Power off an instance and wait until stopped."""
        try:
            self._request("POST", f"/instances/{server_id}/halt")
            logger.info(f"✅ [Vultr] Instance power off requested: {server_id}")
            return self._wait_for_status(server_id, ["off", "stopped"])
        except Exception as e:
            return Err(f"Power off failed: {e}")

    def reboot(self, server_id: str) -> Result[bool, str]:
        """Reboot an instance and wait until running."""
        try:
            self._request("POST", f"/instances/{server_id}/reboot")
            logger.info(f"✅ [Vultr] Instance reboot requested: {server_id}")
            return self._wait_for_status(server_id, ["running"])
        except Exception as e:
            return Err(f"Reboot failed: {e}")

    def resize(self, server_id: str, server_type: str) -> Result[bool, str]:
        """Resize an instance to a new plan and wait until running."""
        try:
            self._request("PATCH", f"/instances/{server_id}", json={"plan": server_type})
            logger.info(f"✅ [Vultr] Instance resize requested: {server_id} -> {server_type}")
            return self._wait_for_status(server_id, ["running"])
        except Exception as e:
            return Err(f"Resize failed: {e}")

    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKeyResult, str]:
        """Upload an SSH key. Replaces if name exists with different content."""
        try:
            # Check for existing key with same name
            resp = self._request("GET", "/ssh-keys")
            existing_keys: list[dict[str, Any]] = resp.json().get("ssh_keys", [])

            for key in existing_keys:
                if key.get("name") == name:
                    if key.get("ssh_key", "").strip() != public_key.strip():
                        logger.warning(f"⚠️ [Vultr] SSH key '{name}' exists with different content, replacing")
                        self._request("DELETE", f"/ssh-keys/{key['id']}")
                    else:
                        return Ok(SSHKeyResult(
                            key_id=key["id"],
                            name=name,
                            fingerprint=key.get("fingerprint", ""),
                        ))

            resp = self._request("POST", "/ssh-keys", json={"name": name, "ssh_key": public_key})
            data: dict[str, Any] = resp.json().get("ssh_key", {})
            logger.info(f"✅ [Vultr] SSH key uploaded: {name}")
            return Ok(SSHKeyResult(
                key_id=data.get("id", ""),
                name=name,
                fingerprint=data.get("fingerprint", ""),
            ))
        except Exception as e:
            return Err(f"SSH key upload failed: {e}")

    def delete_ssh_key(self, name: str) -> Result[bool, str]:
        """Delete an SSH key by name."""
        try:
            resp = self._request("GET", "/ssh-keys")
            existing_keys: list[dict[str, Any]] = resp.json().get("ssh_keys", [])

            for key in existing_keys:
                if key.get("name") == name:
                    self._request("DELETE", f"/ssh-keys/{key['id']}")
                    logger.info(f"✅ [Vultr] SSH key deleted: {name}")
                    return Ok(True)

            return Ok(True)  # Already gone
        except Exception as e:
            return Err(f"SSH key deletion failed: {e}")

    def create_firewall(
        self, name: str, rules: list[FirewallRule], labels: dict[str, str] | None = None
    ) -> Result[str, str]:
        """Create a Vultr firewall group with rules. Returns firewall group ID."""
        try:
            resp = self._request("POST", "/firewalls", json={"description": name})
            group: dict[str, Any] = resp.json().get("firewall_group", {})
            group_id: str = group.get("id", "")

            for rule in rules:
                cidrs = rule.source_ips if rule.source_ips else ["0.0.0.0/0"]
                for cidr in cidrs:
                    network = ipaddress.ip_network(cidr, strict=False)
                    ip_type = "v4" if network.version == IPV4_VERSION else "v6"
                    rule_payload: dict[str, Any] = {
                        "ip_type": ip_type,
                        "protocol": rule.protocol,
                        "port": rule.port,
                        "subnet": str(network.network_address),
                        "subnet_size": network.prefixlen,
                        "notes": rule.description,
                    }
                    self._request("POST", f"/firewalls/{group_id}/rules", json=rule_payload)

            logger.info(f"✅ [Vultr] Firewall group created: {name} (id={group_id})")
            return Ok(group_id)
        except Exception as e:
            return Err(f"Firewall creation failed: {e}")

    def delete_firewall(self, firewall_id: str) -> Result[bool, str]:
        """Delete a firewall group by ID. Returns Ok(True) if already gone (404)."""
        try:
            self._request("DELETE", f"/firewalls/{firewall_id}")
            logger.info(f"✅ [Vultr] Firewall group deleted: {firewall_id}")
            return Ok(True)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTP_NOT_FOUND:
                logger.info(f"✅ [Vultr] Firewall group already gone: {firewall_id}")
                return Ok(True)
            logger.error(f"🔥 [Vultr] Firewall deletion failed: {e}")
            return Err(f"Firewall deletion failed: {e}")
        except Exception as e:
            return Err(f"Firewall deletion failed: {e}")

    def get_locations(self) -> Result[Sequence[LocationInfo], str]:
        """Get all available Vultr regions."""
        try:
            resp = self._request("GET", "/regions")
            regions: list[dict[str, Any]] = resp.json().get("regions", [])
            locations: list[LocationInfo] = [
                LocationInfo(
                    name=r.get("id", ""),
                    description=r.get("city", ""),
                    country=r.get("country", ""),
                    city=r.get("city", ""),
                )
                for r in regions
            ]
            return Ok(locations)
        except Exception as e:
            return Err(f"Failed to get locations: {e}")

    def get_server_types(self) -> Result[Sequence[ServerTypeInfo], str]:
        """Get all available Vultr plans."""
        try:
            resp = self._request("GET", "/plans")
            plans: list[dict[str, Any]] = resp.json().get("plans", [])
            server_types: list[ServerTypeInfo] = [
                ServerTypeInfo(
                    name=p.get("id", ""),
                    description=f"{p.get('vcpu_count', 0)} vCPU / {p.get('ram', 0)}MB RAM / {p.get('disk', 0)}GB",
                    vcpus=p.get("vcpu_count", 0),
                    memory_gb=round(p.get("ram", 0) / 1024, 1),
                    disk_gb=p.get("disk", 0),
                )
                for p in plans
            ]
            return Ok(server_types)
        except Exception as e:
            return Err(f"Failed to get server types: {e}")


    # =========================================================================
    # Snapshot operations (stubs — not yet implemented for Vultr)
    # =========================================================================

    def create_snapshot(self, server_id: str, name: str) -> Result[str, str]:
        """Create a server snapshot. Not yet implemented for Vultr."""
        return Err("Snapshot creation not yet implemented for Vultr")

    def restore_snapshot(self, server_id: str, snapshot_id: str) -> Result[bool, str]:
        """Restore a server from a snapshot. Not yet implemented for Vultr."""
        return Err("Snapshot restore not yet implemented for Vultr")

    def list_snapshots(self, server_id: str) -> Result[list[dict[str, Any]], str]:
        """List snapshots for a server. Not yet implemented for Vultr."""
        return Err("List snapshots not yet implemented for Vultr")

    def delete_snapshot(self, snapshot_id: str) -> Result[bool, str]:
        """Delete a snapshot by ID. Not yet implemented for Vultr."""
        return Err("Snapshot deletion not yet implemented for Vultr")


# Register Vultr as a cloud gateway provider
register_cloud_gateway("vultr", VultrService)


# Factory function
def get_vultr_service(token: str) -> VultrService:
    """Create a VultrService instance with the given API token."""
    return VultrService(token=token)
