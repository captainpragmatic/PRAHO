"""Inspect and approve exact cloud resources before any teardown side effect."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from apps.audit.services import AuditContext, AuditEventData, AuditService

from .cloud_destroy_models import CloudResourceOwnership, CloudResourceRetention, NodeDestroyPlan
from .cloud_destroy_policy import DestroyDecision, build_destroy_decisions, inventory_digest
from .cloud_gateway import get_cloud_gateway
from .cloud_resource_inventory import CloudResource, CloudResourceClient, ResourceCapabilities
from .deployment_lifecycle import (
    OperationLease,
    OperationOwnershipLostError,
    provider_token_fingerprint,
    recorded_provider_resources,
)
from .models import NodeDeployment
from .permissions import can_destroy_nodes

if TYPE_CHECKING:
    from apps.users.models import User

MAX_DESTROY_REASON_LENGTH = 2000
PROVISIONING_CLEANUP_STATES = frozenset(
    {
        "provisioning_node",
        "configuring_dns",
        "installing_panel",
        "configuring_backups",
        "validating",
    }
)


def assert_resource_cleanup_owner(
    current: NodeDeployment, lease: OperationLease, *, provisioning_compensation: bool = False
) -> None:
    """The original provisioning lease may compensate only its still-unregistered attempt."""
    allowed = current.status == "destroying"
    if provisioning_compensation:
        allowed = (
            lease.kind in {"deploy", "retry"}
            and current.operation_kind == lease.kind
            and current.status in PROVISIONING_CLEANUP_STATES
            and current.registration_state == "none"
            and current.virtualmin_server_id is None
        )
    if current.pk != lease.deployment_id or current.operation_token != lease.token or not allowed:
        raise OperationOwnershipLostError("Provider cleanup no longer owns this deployment phase")


@dataclass(frozen=True)
class DestroyApproval:
    hostname: str
    digest: str
    restore_point_policy: str
    reason: str
    retention_mappings: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DestroyPreview:
    digest: str
    token_fingerprint: str
    server_ids: tuple[str, ...]
    resources: list[CloudResource]
    ownership: dict[str, str]
    decisions: list[DestroyDecision]
    capabilities: ResourceCapabilities

    @property
    def options(self) -> list[dict[str, str]]:
        """Show both exact outcomes before the operator selects a retention policy."""
        keep = build_destroy_decisions(self.resources, set(self.ownership), self.server_ids, "keep", self.capabilities)
        delete = {
            item.key: item
            for item in build_destroy_decisions(
                self.resources, set(self.ownership), self.server_ids, "delete", self.capabilities
            )
        }
        return [{"key": item.key, "keep": item.reason, "delete": delete[item.key].reason} for item in keep]


def record_resource_ownership(
    deployment: NodeDeployment,
    kind: str,
    resource_id: str,
    provenance: str,
) -> CloudResourceOwnership:
    if not deployment.provider_token_fingerprint:
        raise ValidationError(_("Record the creating provider credential before resource ownership."))
    record, created = CloudResourceOwnership.objects.get_or_create(
        provider_id=deployment.provider_id,
        token_fingerprint=deployment.provider_token_fingerprint,
        kind=kind,
        resource_id=resource_id,
        defaults={
            "deployment": deployment,
            "provenance": provenance,
            "deployment_correlation_id": deployment.correlation_id,
        },
    )
    if record.deployment_id != deployment.pk or record.deployment_correlation_id != deployment.correlation_id:
        raise ValidationError(_("This resource already belongs to a different deployment."))
    if created:
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=record,
                description="Recorded exact provider resource ownership",
                new_values={
                    "deployment_id": deployment.pk,
                    "kind": kind,
                    "resource_id": resource_id,
                    "provenance": provenance,
                },
            ),
            context=AuditContext(actor_type="system"),
        )
    return record


def resource_ownership(deployment: NodeDeployment, resources: list[CloudResource], fingerprint: str) -> dict[str, str]:
    proofs = {
        f"{item.kind}:{item.resource_id}": item.provenance
        for item in CloudResourceOwnership.objects.filter(
            deployment=deployment,
            provider_id=deployment.provider_id,
            token_fingerprint=fingerprint,
            deployment_correlation_id=deployment.correlation_id,
        )
    }
    if deployment.provider_token_fingerprint != fingerprint:
        return proofs
    if deployment.external_node_id and deployment.server_create_state == "created":
        proofs[f"server:{deployment.external_node_id}"] = "persisted_create_response"
    for firewall_id in recorded_provider_resources(deployment)["firewall_ids"]:
        proofs[f"firewall:{firewall_id}"] = "persisted_creation_log"
    correlation = str(deployment.correlation_id)
    for resource in resources:
        if (resource.kind in {"server", "ssh_key"} and resource.labels.get("praho-deployment") == correlation) or (
            resource.kind == "firewall" and resource.labels.get("deployment-id") == correlation
        ):
            proofs[resource.key] = "creating_token_and_deployment_label"
    return proofs


def inspect_destroy(
    deployment: NodeDeployment,
    api_token: str,
    *,
    client: CloudResourceClient | None = None,
) -> DestroyPreview:
    deployment = NodeDeployment.objects.select_related("provider").get(pk=deployment.pk)
    fingerprint = provider_token_fingerprint(api_token)
    if not api_token or (
        deployment.provider_token_fingerprint and deployment.provider_token_fingerprint != fingerprint
    ):
        raise ValidationError(_("Restore the creating provider credential before reviewing destruction."))
    server_ids = {deployment.external_node_id} if deployment.external_node_id else set()
    server_ids.update(
        CloudResourceOwnership.objects.filter(
            deployment=deployment,
            token_fingerprint=fingerprint,
            kind="server",
            deployment_correlation_id=deployment.correlation_id,
        ).values_list("resource_id", flat=True)
    )
    previous = deployment.destroy_plans.filter(
        token_fingerprint=fingerprint, deployment_correlation_id=deployment.correlation_id
    ).first()
    if previous:
        server_ids.update(previous.server_ids)
    if client is None:
        client = get_cloud_gateway(deployment.provider.provider_type, api_token).resource_client()
    initial_server_ids = tuple(sorted(server_ids))
    result = client.inventory(initial_server_ids)
    if result.is_err():
        raise ValidationError(
            _("Provider resource inventory is incomplete: %(detail)s") % {"detail": result.unwrap_err()}
        )
    resources = result.unwrap()
    proofs = resource_ownership(deployment, resources, fingerprint)
    server_ids.update(item.resource_id for item in resources if item.kind == "server" and item.key in proofs)
    # Label discovery can recover an unrecorded create; fetch its server-scoped backup inventory too.
    if tuple(sorted(server_ids)) != initial_server_ids:
        result = client.inventory(tuple(sorted(server_ids)))
        if result.is_err():
            raise ValidationError(_("Provider resource inventory is incomplete."))
        resources = result.unwrap()
        proofs = resource_ownership(deployment, resources, fingerprint)
    payload = {
        "inventory": inventory_digest(deployment.provider.provider_type, fingerprint, resources),
        "deployment": deployment.pk,
        "hostname": deployment.hostname,
        "deployment_correlation_id": str(deployment.correlation_id),
        "ownership": proofs,
        "server_ids": sorted(server_ids),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    decisions = build_destroy_decisions(
        resources, set(proofs), tuple(sorted(server_ids)), "preserve", client.capabilities
    )
    return DestroyPreview(
        digest, fingerprint, tuple(sorted(server_ids)), resources, proofs, decisions, client.capabilities
    )


def protect_retained_resource(plan: NodeDestroyPlan, kind: str, resource_id: str) -> None:
    record, created = CloudResourceRetention.objects.get_or_create(
        provider_id=plan.provider_id,
        token_fingerprint=plan.token_fingerprint,
        kind=kind,
        resource_id=resource_id,
        defaults={"plan": plan},
    )
    if created:
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=record,
                description="Protected operator-retained provider restore point from automatic expiry",
                new_values={"plan_id": str(plan.pk), "kind": kind, "resource_id": resource_id},
            ),
            context=AuditContext(user=plan.actor, actor_type="user" if plan.actor_id else "system"),
        )


@transaction.atomic
def approve_destroy(
    deployment: NodeDeployment,
    api_token: str,
    actor: User,
    approval: DestroyApproval,
) -> NodeDestroyPlan:
    if not can_destroy_nodes(actor):
        raise PermissionDenied(_("Node destruction permission is required."))
    locked = NodeDeployment.objects.select_for_update().get(pk=deployment.pk)
    if locked.hostname != approval.hostname:
        raise ValidationError(_("The confirmation must match the exact deployment hostname."))
    if (
        not approval.reason.strip()
        or len(approval.reason) > MAX_DESTROY_REASON_LENGTH
        or approval.restore_point_policy not in {"keep", "delete"}
    ):
        raise ValidationError(_("Choose keep or delete and explain the provider restore-point decision."))
    if locked.status not in {"completed", "failed", "stopped"} and not (
        locked.status == "destroying" and locked.needs_reconciliation
    ):
        raise ValidationError(_("Wait for the active deployment operation before approving destruction."))
    preview = inspect_destroy(locked, api_token)
    if preview.digest != approval.digest:
        raise ValidationError(_("The provider inventory or ownership changed; review its current resources again."))
    return _store_destroy_plan(locked, preview, approval, actor)


def _mapped_restore_points(
    preview: DestroyPreview,
    approval: DestroyApproval,
    decisions: list[DestroyDecision],
) -> list[DestroyDecision]:
    required = (
        {
            item.resource_id
            for item in decisions
            if item.kind == "backup" and item.action == "manual" and item.blocks_parent
        }
        if approval.restore_point_policy == "keep" and preview.capabilities.backup_retention == "manual"
        else set()
    )
    mappings = approval.retention_mappings
    if set(mappings) != required or len(set(mappings.values())) != len(mappings):
        raise ValidationError(
            _("Prepare and verify the exact provider backup snapshot mapping before keeping these backups.")
        )
    if not mappings:
        return decisions
    prepared = {
        item.resource_id: item
        for item in preview.resources
        if item.kind == "snapshot" and item.state in {"complete", "available"}
    }
    result = {item.key: item for item in decisions}
    for backup_id, snapshot_id in mappings.items():
        resource = prepared.get(snapshot_id)
        if resource is None or set(resource.source_ids) - set(preview.server_ids):
            raise ValidationError(_("The mapped snapshot is missing, pending, or belongs to a different source."))
        result[f"backup:{backup_id}"] = DestroyDecision(
            "backup",
            backup_id,
            "await_expiry",
            _("Track the original provider backup until expiry; retain its operator-verified durable snapshot copy."),
        )
        result[f"snapshot:{snapshot_id}"] = DestroyDecision(
            "snapshot",
            snapshot_id,
            "keep",
            _("Retain the durable snapshot prepared from this exact backup in the provider console; charges continue."),
        )
    return sorted(result.values(), key=lambda item: item.key)


def _store_destroy_plan(
    locked: NodeDeployment,
    preview: DestroyPreview,
    approval: DestroyApproval,
    actor: User | None,
) -> NodeDestroyPlan:
    """The caller holds the deployment lock; preserve immutable approvals across retries."""
    decisions = build_destroy_decisions(
        preview.resources,
        set(preview.ownership),
        preview.server_ids,
        approval.restore_point_policy,
        preview.capabilities,
    )
    decisions = _mapped_restore_points(preview, approval, decisions)
    for key, provenance in preview.ownership.items():
        kind, _separator, resource_id = key.partition(":")
        record_resource_ownership(locked, kind, resource_id, provenance)
    plan = NodeDestroyPlan.objects.create(
        deployment=locked,
        provider_id=locked.provider_id,
        provider_type=locked.provider.provider_type,
        actor=actor,
        hostname=locked.hostname,
        token_fingerprint=preview.token_fingerprint,
        deployment_correlation_id=locked.correlation_id,
        digest=preview.digest,
        server_ids=list(preview.server_ids),
        restore_point_policy=approval.restore_point_policy,
        inventory=[asdict(resource) for resource in preview.resources],
        decisions=[asdict(item) for item in decisions],
        retention_mappings=dict(approval.retention_mappings),
        reason=approval.reason.strip(),
    )
    for decision in decisions:
        if decision.action == "keep":
            protect_retained_resource(plan, decision.kind, decision.resource_id)
    AuditService.log_event(
        AuditEventData(
            event_type="configuration_changed",
            content_object=plan,
            description="Approved exact provider resources and restore-point choices for node destruction",
            new_values={
                "digest": plan.digest,
                "restore_point_policy": plan.restore_point_policy,
                "deployment_id": locked.pk,
                "resource_count": len(decisions),
            },
        ),
        context=AuditContext(user=actor, actor_type="user" if actor else "system"),
    )
    return plan


@transaction.atomic
def plan_for_teardown(  # noqa: PLR0913 -- approved plan and provisioning compensation have separate authority
    deployment: NodeDeployment,
    lease: OperationLease,
    api_token: str,
    client: CloudResourceClient,
    plan_id: UUID | None = None,
    *,
    provisioning_compensation: bool = False,
) -> NodeDestroyPlan:
    locked = NodeDeployment.objects.select_for_update().get(pk=deployment.pk)
    assert_resource_cleanup_owner(locked, lease, provisioning_compensation=provisioning_compensation)
    fingerprint = provider_token_fingerprint(api_token)
    if not api_token or locked.provider_token_fingerprint != fingerprint:
        raise ValidationError(_("Restore the creating provider credential before provider cleanup."))
    plans = locked.destroy_plans.filter(token_fingerprint=fingerprint, deployment_correlation_id=locked.correlation_id)
    if plan_id is not None:
        plan = plans.filter(pk=plan_id).first()
        if plan is None:
            raise ValidationError(_("The approved destroy plan does not match this deployment lifetime or credential."))
        return plan
    existing = plans.first()
    if existing:
        return existing
    preview = inspect_destroy(locked, api_token, client=client)
    approval = DestroyApproval(
        locked.hostname,
        preview.digest,
        "preserve",
        "Unattended cleanup preserves durable restore points and requires review before deleting provider backups.",
    )
    return _store_destroy_plan(locked, preview, approval, None)
