"""Pure decisions for an exact provider inventory; approval and execution persist separately."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Literal

from .cloud_resource_inventory import CloudResource, ResourceCapabilities, ResourceKind

DestroyAction = Literal["delete", "keep", "convert", "parent_delete", "await_expiry", "manual"]
RESTORE_POINT_KINDS = frozenset({"backup", "snapshot", "volume_snapshot"})


@dataclass(frozen=True)
class DestroyDecision:
    kind: ResourceKind
    resource_id: str
    action: DestroyAction
    reason: str
    blocks_parent: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.resource_id}"


@dataclass(frozen=True)
class _DestroyContext:
    servers: set[str]
    shared_images: set[str]
    policy: str
    capabilities: ResourceCapabilities


def inventory_digest(provider: str, token_fingerprint: str, resources: list[CloudResource]) -> str:
    payload = {
        "provider": provider,
        "token_fingerprint": token_fingerprint,
        "resources": [asdict(item) for item in sorted(resources, key=lambda resource: resource.key)],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _restore_decision(
    resource: CloudResource,
    policy: str,
    capabilities: ResourceCapabilities,
) -> DestroyDecision:
    if resource.kind == "backup":
        if policy == "preserve":
            return DestroyDecision(
                resource.kind,
                resource.resource_id,
                "manual",
                "An operator must choose how to retain or delete this provider backup before VM deletion.",
                True,
            )
        if policy == "keep":
            if capabilities.backup_retention == "convert":
                return DestroyDecision(
                    resource.kind,
                    resource.resource_id,
                    "convert",
                    "Convert this existing backup and verify its durable snapshot before any teardown; storage charges continue.",
                )
            return DestroyDecision(
                resource.kind,
                resource.resource_id,
                "manual",
                "Prepare a durable snapshot in the provider console and verify the exact backup-to-snapshot mapping.",
                True,
            )
        backup_actions: dict[str, DestroyAction] = {
            "parent": "parent_delete",
            "delete": "delete",
            "expiry": "await_expiry",
        }
        action = backup_actions[capabilities.backup_deletion]
        reason = {
            "parent_delete": "The provider deletes this backup with the VM; confirm its absence after deletion.",
            "delete": "Delete this exact provider backup and confirm its absence.",
            "await_expiry": "The provider expires this backup; report it awaiting expiry until authoritative absence is verified.",
        }[action]
        return DestroyDecision(resource.kind, resource.resource_id, action, reason)
    if policy in {"keep", "preserve"}:
        return DestroyDecision(
            resource.kind,
            resource.resource_id,
            "keep",
            "Retain this durable provider restore point; storage charges continue and automatic expiry is suppressed.",
        )
    return DestroyDecision(
        resource.kind,
        resource.resource_id,
        "delete",
        "Delete this exact provider restore point and confirm its absence.",
    )


def _resource_decision(
    resource: CloudResource,
    owned: bool,
    context: _DestroyContext,
) -> DestroyDecision:
    blocks_parent = resource.kind in {"server", "backup"} or (resource.kind == "primary_ip" and resource.auto_delete)
    if (
        resource.protected
        or set(resource.attached_to) - context.servers
        or (resource.kind in {"snapshot", "custom_image", "volume_snapshot"} and resource.key in context.shared_images)
    ):
        return DestroyDecision(
            resource.kind,
            resource.resource_id,
            "manual",
            "Preserve this protected or shared resource; it requires separate reconciliation.",
            blocks_parent,
        )
    if not owned or not resource.attachments_known:
        return DestroyDecision(
            resource.kind,
            resource.resource_id,
            "manual",
            "Preserve this resource: exclusive ownership and attachments are not proven.",
            blocks_parent,
        )
    if resource.kind in RESTORE_POINT_KINDS:
        return _restore_decision(resource, context.policy, context.capabilities)
    return DestroyDecision(
        resource.kind,
        resource.resource_id,
        "delete",
        "Delete this proven exclusive resource by ID, then verify its absence.",
    )


def build_destroy_decisions(
    resources: list[CloudResource],
    owned_keys: set[str],
    server_ids: tuple[str, ...],
    restore_point_policy: str,
    capabilities: ResourceCapabilities,
) -> list[DestroyDecision]:
    if restore_point_policy not in {"keep", "delete", "preserve"}:
        raise ValueError("Choose keep or delete for provider backups and snapshots")
    servers = set(server_ids)
    owned_volumes = {item.resource_id for item in resources if item.kind == "volume" and item.key in owned_keys}
    shared_images = {
        f"{kind}:{image}"
        for item in resources
        if item.kind == "server" and item.resource_id not in servers
        for image in item.source_ids
        for kind in ("snapshot", "custom_image")
    }
    shared_images.update(
        f"volume_snapshot:{snapshot}"
        for item in resources
        if item.kind == "volume" and item.key not in owned_keys
        for snapshot in item.source_ids
    )
    context = _DestroyContext(servers, shared_images, restore_point_policy, capabilities)
    decisions: list[DestroyDecision] = []
    for resource in sorted(resources, key=lambda item: item.key):
        origin_owned = (
            resource.kind in {"backup", "snapshot"}
            and bool(resource.source_ids)
            and set(resource.source_ids) <= servers
        ) or (
            resource.kind == "volume_snapshot"
            and bool(resource.source_ids)
            and set(resource.source_ids) <= owned_volumes
        )
        owned = resource.key in owned_keys or origin_owned
        related = owned or bool(set(resource.attached_to) & servers)
        if resource.kind == "server":
            related = resource.resource_id in servers
        if related:
            decisions.append(_resource_decision(resource, owned, context))
    return decisions
